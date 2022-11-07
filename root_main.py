"""Lambda function to used to rotate a single MySQL user"""
import logging
from typing import Dict

from boto3 import client

import src.common.sentry_wrapper as sentry_wrapper
import src.common.aws_wrapper as aws_wrapper
from src.common.sentry_ignored_exception import SentryIgnoredException
import src.common.constants as constants
import src.common.mysql.mysql_helper as mysql_helper
import src.mysql_single_user_secret.helpers.single_user_connection_helper as single_user_connection_helper
from src.common.mysql.constants import EXCLUDED_CHARACTERS
from src.common.mysql.mysql_single_user_secret import MySQLSingleUserSecret
from src.common.secret_stage import SecretStage
from src.common.common_utils import validate_lambda_can_access_ssm_parameter

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sentry_wrapper.init_sentry()


def lambda_handler(event: Dict, context: Dict):
    """Secrets Manager MySQL single User Handler

    This handler takes a single RDS MySQL user credential. It logs into the database as the user
    and rotates the user's own password, immediately invalidating the user's previous password.

    The Secret is expected to be a JSON string with the following format:
    {
        'host': <required: instance host name>,
        'username': <required: username>,
        'password': <required: password>,
        'dbname': <optional: database name>,
        'port': <optional: if not specified, default port 3306 will be used>
        'ssm_parameter_to_update_kms_key_id': <optional: the id of the kms key use to encrypt the ssm parameter>
        'ssm_parameter_to_update_name': <optional: the name of the ssm parameter to update>
    }
    :param event: A dictionary containing the event parameters. It must contains:
        - SecretId: The secret ARN or identifier
        - ClientRequestToken: The ClientRequestToken of the secret version
        - Step: The rotation step (createSecret, setSecret, testSecret, or finishSecret)
    :param context: The Lambda runtime information
    :raise ValueError: The secret is not properly configured for rotation or the rotation step is invalid
    :raise KeyError: The secret json or the event does not contain the expected keys
    """

    logging.info("Received event: '%s'", event)
    logging.info("Received context: '%s'", context)
    secret_arn = event["SecretId"]
    client_request_token = event["ClientRequestToken"]
    step = event["Step"]

    secret_manager_client = client("secretsmanager")

    metadata = secret_manager_client.describe_secret(SecretId=secret_arn)

    if not aws_wrapper.secret_metadata_is_staged_correctly(metadata, client_request_token):
        return

    if step == "createSecret":
        create_secret(secret_manager_client, secret_arn, client_request_token)

    elif step == "setSecret":
        set_secret(secret_manager_client, secret_arn, client_request_token)

    elif step == "testSecret":
        test_secret(secret_manager_client, secret_arn, client_request_token)

    elif step == "finishSecret":
        finish_secret(secret_manager_client, secret_arn, client_request_token)

    else:
        raise ValueError("Invalid step parameter %s for secret %s" % (step, secret_arn))


def create_secret(secret_manager_client: client, secret_arn: str, token: str) -> None:
    """Generate a new secret

    This method first checks for the existence of a pending secret for the token passed in parameter.
    If one does not exist, it will generate a new secret and put it with the passed in token.

    :param secret_manager_client: The secrets manager service client
    :param secret_arn: The secret ARN or other identifier
    :param token: The stage identifying the secret version
    """
    try:
        MySQLSingleUserSecret.from_secret(secret_manager_client, secret_arn, SecretStage.Pending, token)
        logging.info("createSecret: Successfully retrieved secret for %s.", secret_arn)
    except secret_manager_client.exceptions.ResourceNotFoundException:
        current_secret = MySQLSingleUserSecret.from_secret(secret_manager_client, secret_arn, SecretStage.Current)

        if constants.SSM_PARAMETER_TO_UPDATE_NAME in current_secret.additional_parameters:
            validate_lambda_can_access_ssm_parameter(
                client("ssm"), current_secret.additional_parameters[constants.SSM_PARAMETER_TO_UPDATE_NAME], secret_arn
            )

        random_password = secret_manager_client.get_random_password(ExcludeCharacters=EXCLUDED_CHARACTERS)
        current_secret.password = random_password["RandomPassword"]

        secret_manager_client.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=str(current_secret),
            VersionStages=[SecretStage.Pending.value],
        )

        logging.info("createSecret: Successfully put secret for ARN %s and version %s.", secret_arn, token)


def set_secret(secret_manager_client: client, secret_arn: str, token: str) -> None:
    """Set the pending secret in the database

    This method tries to login to the database with the pending secret. If that fails, it
    tries to login with the current, and previous secrets as a  fallback.
    On success, it sets the pending password as the user password in the database.

    :param secret_manager_client: The secrets manager service client
    :param secret_arn: The secret ARN or other identifier
    :param token: The stage identifying the secret version
    :raise ValueError: If a connection cannot be establish
    """

    # Try to login with the pending secret, if it succeeds skip updating the password because it is already set
    try:
        connection = single_user_connection_helper.get_connection_with_pending_secret_stage(
            secret_manager_client, secret_arn, token
        )
    except secret_manager_client.exceptions.ResourceNotFoundException as exception:
        logging.warning(
            f"setSecret: {SecretStage.Pending.value} secret with arn '{secret_arn}' has not been found probably due to"
            f" cache propagation. Exiting Lambda with exception to retry later."
        )
        raise SentryIgnoredException from exception

    if connection:
        connection.close()
        logging.info(
            "setSecret: the pending secret is already set as password in MySQL DB for secret arn %s.", secret_arn
        )

    else:
        # Try to get a connection from the current secret
        connection = single_user_connection_helper.get_connection_with_current_secret_stage(
            secret_manager_client, secret_arn
        )

        if not connection:
            logging.warning(
                "setSecret: Unable to log into the database with current secret of secret arn %s", secret_arn
            )
            # Fallback to the previous secret
            connection = single_user_connection_helper.get_connection_with_previous_secret_stage(
                secret_manager_client, secret_arn
            )

        if connection:
            try:
                pending_secret = MySQLSingleUserSecret.from_secret(
                    secret_manager_client, secret_arn, SecretStage.Pending, token
                )
            except secret_manager_client.exceptions.ResourceNotFoundException as exception:
                logging.warning(
                    f"setSecret: {SecretStage.Pending.value} secret with arn '{secret_arn}' has not been found probably"
                    f" due to cache propagation. Exiting Lambda with exception to retry later."
                )
                connection.close()
                raise SentryIgnoredException from exception

            try:
                # Update the password to the pending one
                with connection.cursor() as cursor:
                    cursor.execute("SELECT VERSION()")

                    # dcignore: test
                    cursor.execute(
                        f"SET PASSWORD = {mysql_helper.get_password_option(cursor.fetchone()[0])}",  # type: ignore
                        pending_secret.password,  # type: ignore
                    )
                    connection.commit()
                    logging.info(
                        "setSecret: Successfully set password for user %s in MySQL DB for secret arn %s.",
                        pending_secret.username,
                        secret_arn,
                    )
            finally:
                connection.close()
        else:
            raise ValueError(
                f"Unable to log into database with previous, current, or pending secret of secret arn {secret_arn}"
            )


def test_secret(secret_manager_client: client, secret_arn: str, token: str) -> None:
    """Test the pending secret against the database

    This method tries to log into the database with the pending staged secret.
    It runs a permissions check to ensure the user has the right permissions.

    :param secret_manager_client: The secrets manager service client
    :param secret_arn: The secret ARN or other identifier
    :param token: The stage identifying the secret version
    :raise ValueError: If a connection cannot be establish
    """

    try:
        connection = single_user_connection_helper.get_connection_with_pending_secret_stage(
            secret_manager_client, secret_arn, token
        )
    except secret_manager_client.exceptions.ResourceNotFoundException as exception:
        logging.warning(
            f"setSecret: {SecretStage.Pending.value} secret with arn '{secret_arn}' has not been found probably"
            f" due to cache propagation. Exiting Lambda with exception to retry later."
        )
        raise SentryIgnoredException from exception

    if connection:
        logging.info("testSecret: Successfully signed into MySQL DB with pending secret in %s.", secret_arn)
        try:
            # Validates the user access.
            with connection.cursor() as cursor:
                cursor.execute("SELECT NOW()")
                connection.commit()
        finally:
            connection.close()
    else:
        raise ValueError(f"Unable to log into database with pending secret of secret ARN {secret_arn}")


def finish_secret(secret_manager_client: client, secret_arn: str, token: str) -> None:
    """Finish the rotation by marking the pending secret as current

    This method finishes the secret rotation by staging the secret staged AWSPENDING with the AWSCURRENT stage,
    and call the update for the secret in the AWS Parameter Store.
    Secrets Manager automatically moves the label AWSPREVIOUS to the version that AWSCURRENT was removed from.
    The AWSPREVIOUS secret is still working for the product that is currently running.

    :param secret_manager_client: The secrets manager service client
    :param secret_arn: The secret ARN or other identifier
    :param token: The stage identifying the secret version
    :raise ParamValidationError: current_version is not found  and cannot be None
    """

    metadata = secret_manager_client.describe_secret(SecretId=secret_arn)
    current_version = None

    for version in metadata["VersionIdsToStages"]:
        if SecretStage.Current.value in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                logging.info("finishSecret: Version %s already marked as current for %s", version, secret_arn)
                return
            current_version = version
            break

    try:
        secret = MySQLSingleUserSecret.from_secret(secret_manager_client, secret_arn, SecretStage.Pending, token)

    except secret_manager_client.exceptions.ResourceNotFoundException as exception:
        logging.warning(
            f"setSecret: {SecretStage.Pending.value} secret with arn '{secret_arn}' has not been found probably"
            f" due to cache propagation. Exiting Lambda with exception to retry later."
        )
        raise SentryIgnoredException from exception

    # Finalize by staging the secret version current
    secret_manager_client.update_secret_version_stage(
        SecretId=secret_arn,
        VersionStage=SecretStage.Current.value,
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    logging.info("finishSecret: Successfully set current stage to version %s for secret %s.", token, secret_arn)

    _update_ssm_parameter(secret_arn, secret)


def _update_ssm_parameter(secret_arn: str, secret: MySQLSingleUserSecret) -> None:
    """Update the secret in the AWS Parameter Store

    This method update the secret for the service in the AWS Parameter Store if additional parameters
    are given to the  secret to specify the ssm parameter to update

    :param secret_arn: The secret ARN or other identifier
    :param secret: The secret to to update
    """
    if (
        constants.SSM_PARAMETER_TO_UPDATE_KMS_KEY_ID in secret.additional_parameters
        and constants.SSM_PARAMETER_TO_UPDATE_NAME in secret.additional_parameters
    ):
        ssm_parameter_name = secret.additional_parameters[constants.SSM_PARAMETER_TO_UPDATE_NAME]
        aws_wrapper.set_ssm_parameter(
            client("ssm"),
            ssm_parameter_name,
            secret.password,
            secret.additional_parameters[constants.SSM_PARAMETER_TO_UPDATE_KMS_KEY_ID],
        )

        logging.info(
            "Successfully set MySQL Single User Secret in SSM for parameter '%s' for '%s'",
            ssm_parameter_name,
            secret_arn,
        )
    else:
        logging.info("No MySQL Single User Secret to set in SSM for parameter for '%s'", secret_arn)
