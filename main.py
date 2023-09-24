import argparse
import time

import docker
import boto3
from botocore.exceptions import NoCredentialsError


def create_aws_cloudwatch_group(stream_name, group_name, aws_access_key_id, aws_secret_access_key, aws_region):
    cloudwatch = boto3.client(
        'logs',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=aws_region
    )

    try:
        cloudwatch.create_log_group(logGroupName=group_name)
    except cloudwatch.exceptions.ResourceAlreadyExistsException:
        pass

    try:
        cloudwatch.create_log_stream(logGroupName=group_name, logStreamName=stream_name)
    except cloudwatch.exceptions.ResourceAlreadyExistsException:
        pass


def send_logs_to_cloudwatch(logs, stream_name, group_name, aws_access_key_id, aws_secret_access_key, aws_region):
    cloudwatch = boto3.client(
        'logs',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=aws_region
    )

    try:
        response = cloudwatch.describe_log_streams(logGroupName=group_name, logStreamNamePrefix=stream_name)
        sequence_token = response['logStreams'][0]['uploadSequenceToken']
    except Exception:
        sequence_token = None

    try:
        cloudwatch.put_log_events(
            logGroupName=group_name,
            logStreamName=stream_name,
            logEvents=[{'timestamp': int(time.time() * 1000), 'message': logs}],
            sequenceToken=sequence_token
        )
    except NoCredentialsError:
        print("AWS credentials are invalid.")
    except Exception as e:
        print(f"Error sending logs to AWS CloudWatch: {str(e)}")


def main():
    parser = argparse.ArgumentParser(description="Docker container log to AWS CloudWatch")
    parser.add_argument("--docker-image", required=True, help="Name of the Docker image")
    parser.add_argument("--bash-command", required=True, help="Bash command to run inside the Docker image")
    parser.add_argument("--aws-cloudwatch-group", required=True, help="Name of AWS CloudWatch group")
    parser.add_argument("--aws-cloudwatch-stream", required=True, help="Name of AWS CloudWatch stream")
    parser.add_argument("--aws-access-key-id", required=True, help="AWS Access Key ID")
    parser.add_argument("--aws-secret-access-key", required=True, help="AWS Secret Access Key")
    parser.add_argument("--aws-region", required=True, help="AWS region")

    args = parser.parse_args()

    create_aws_cloudwatch_group(args.aws_cloudwatch_stream, args.aws_cloudwatch_group, args.aws_access_key_id,
                                args.aws_secret_access_key, args.aws_region)

    client = docker.from_env()
    container = client.containers.run(args.docker_image, args.bash_command, detach=True, stdout=True, stderr=True)
    while True:
        container.reload()
        if container.status == "exited":
            exit(1)
        if container.status == "running":
            break
        time.sleep(1)

    last_log_position = None
    while container.status == "running":
        logs = container.logs(stdout=True, stderr=True, stream=True, since=last_log_position, follow=True)

        for log in logs:
            log_line = log.decode("utf-8").strip()
            send_logs_to_cloudwatch(
                log_line, args.aws_cloudwatch_stream, args.aws_cloudwatch_group,
                args.aws_access_key_id,
                args.aws_secret_access_key, args.aws_region
            )
        last_log_position = container.attrs["State"]["LogPos"]


if __name__ == "__main__":
    main()
