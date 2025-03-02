import boto3
import boto3.session
import typing

import importlib

from dataclasses import dataclass


@dataclass
class AwsClient:
    region: typing.Optional[str] = None
    profile: typing.Optional[str] = None
    role_arn: typing.Optional[str] = None
    role_session_name: typing.Optional[str] = None
    external_id: typing.Optional[str] = None
    verbose: bool = False
    
    _session: typing.Optional[boto3.session.Session] = None
    _sts_client: typing.Optional[boto3.client] = None
    _role_credentials: typing.Optional[dict] = None

    @property
    def aws_session(self):
        if self._session is None:
            self._session = boto3.session.Session(region_name=self.region, profile_name=self.profile)
            
            # If role ARN is provided, assume the role
            if self.role_arn:
                if self.verbose:
                    print(f"Assuming role: {self.role_arn}")
                
                self._sts_client = self._session.client('sts')
                
                assume_role_kwargs = {
                    'RoleArn': self.role_arn,
                    'RoleSessionName': self.role_session_name or 'aws-log-parser-session'
                }
                
                if self.external_id:
                    assume_role_kwargs['ExternalId'] = self.external_id
                
                self._role_credentials = self._sts_client.assume_role(**assume_role_kwargs)['Credentials']
                
                # Create a new session with the assumed role credentials
                self._session = boto3.session.Session(
                    aws_access_key_id=self._role_credentials['AccessKeyId'],
                    aws_secret_access_key=self._role_credentials['SecretAccessKey'],
                    aws_session_token=self._role_credentials['SessionToken'],
                    region_name=self.region
                )
                
                if self.verbose:
                    print(f"Successfully assumed role: {self.role_arn}")
        
        return self._session

    def aws_client(self, service_name):
        return self.aws_session.client(service_name)

    @property
    def ec2_client(self):
        return self.aws_session.client("ec2")

    @property
    def s3_client(self):
        return self.aws_session.client("s3")

    def get_service(self, service_name):
        module = self.__module__.split(".")
        module.pop(-1)
        package = ".".join(module)

        try:
            module = importlib.import_module(f".{service_name}", package=package)
            service = getattr(module, f"{service_name.title()}Service")
        except (ImportError, AttributeError):
            raise ValueError(f"Unknown service {service_name}")
        return service

    def service_factory(self, service_name):
        return self.get_service(service_name)(aws_client=self)

    @property
    def s3_service(self):
        return self.service_factory("s3")

    def get_tag(self, tags, name):
        for tag in tags:
            if tag["Key"] == name:
                return tag["Value"]


@dataclass
class AwsService:
    aws_client: AwsClient

    def get_tag(self, tags, name):
        for tag in tags:
            if tag["Key"] == name:
                return tag["Value"]
