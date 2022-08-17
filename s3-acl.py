import boto3
import argparse
import sys
from collections import deque
from threading import Thread, Lock
from queue import Queue


lock = Lock()


def safe_print(*args, **kwargs):
    with lock:
        print(*args, **kwargs)


def worker(q):
    while True:
        bucket_name, object_name = q.get()
        check_permissions(bucket_name, object_name)
        q.task_done()


def check_permissions(bucket, key):
    s3 = boto3.resource("s3")

    try:
        object_acl = s3.ObjectAcl(bucket, key)

        for grantee in object_acl.grants:
            if grantee['Grantee']['Type'] != "Group":
                continue
            if 'AllUsers' in grantee['Grantee']['URI']:
                safe_print(f"s3://{bucket}/{key} - AllUsers - {grantee['Permission']}")
                continue
            if 'AuthenticatedUsers' in grantee['Grantee']['URI']:
                safe_print(f"s3://{bucket}/{key} - AuthenticatedUsers - {grantee['Permission']}")
                continue
    except:
        pass


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-a", "--all-buckets", action='store_true', help="get and check all buckets")
    parser.add_argument("-b", "--bucket", help="bucket to check")
    parser.add_argument("-t", "--threads", type=int, default=10, help="number of threads to use")
    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(-1)

    if not (args.all_buckets or args.bucket):
        print("Either --all-buckets or --bucket is required")
        sys.exit(-1)

    '''
    https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html:
    The mechanism in which Boto3 looks for credentials is to search through a list of possible locations and stop as 
    soon as it finds credentials. The order in which Boto3 searches for credentials is:
    
    - Passing credentials as parameters in the boto.client() method
    - Passing credentials as parameters when creating a Session object
    - Environment variables
    - Shared credential file (~/.aws/credentials)
    - AWS config file (~/.aws/config)
    - Assume Role provider
    - Boto2 config file (/etc/boto.cfg and ~/.boto)
    - Instance metadata service on an Amazon EC2 instance that has an IAM role configured.
    '''
    s3resource = boto3.resource("s3")

    buckets = deque()
    object_queue = Queue()

    if args.all_buckets:
        s3client = boto3.client("s3")
        response = s3client.list_buckets()

        for bucket in response['Buckets']:
            buckets.append(bucket['Name'])

    if args.bucket:
        if args.bucket not in buckets:
            buckets.append(args.bucket)

    for i in range(args.threads):
        t = Thread(target=worker, args=(object_queue,))
        t.daemon = True
        t.start()

    for bucket in buckets:
        for s3_object in s3resource.Bucket(bucket).objects.all():
            if not s3_object.key.endswith("/"):
                object_queue.put((s3_object.bucket_name, s3_object.key))

    object_queue.join()


if __name__ == "__main__":
    main()

