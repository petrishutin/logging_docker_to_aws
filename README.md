### Backend Engineer Test Task
Write a Python program that accepts the following arguments:
Arguments
1. A name of a Docker image
2. A bash command (to run inside the Docker image)
3. A name of an AWS CloudWatch group
4. A name of an AWS CloudWatch stream
5. AWS credentials
6. A name of an AWS region

Example:

```bash
python main.py --docker-image python --bash-command $'pip install pip -U && pip install tqdm && python -c \"import time\ncounter = 0\nwhile True:\n\tprint(counter)\n\tcounter += 1\n\ttime.sleep(1)\"' --aws-cloudwatch-group test-task-group-1 --aws-cloudwatch-stream test-task-stream-1 --aws-access-key-id ... --aws-secret-access-key ... --aws-region ...
```

Functionality
- The program should create a Docker container using the given Docker image name, and
the given bash command
- The program should handle the output logs of the container and send them to the given
AWS CloudWatch group/stream using the given AWS credentials. If the corresponding
AWS CloudWatch group or stream does not exist, it should create it using the given
AWS credentials.

Other requirements
- The program should behave properly regardless of how much or what kind of logs the
container outputs.
- The program should gracefully handle errors and interruptions.

