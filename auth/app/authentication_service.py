import os
import jwt
from datetime import datetime, timedelta, timezone
import grpc
from concurrent import futures
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker, declarative_base
from werkzeug.security import generate_password_hash, check_password_hash
import authentication_pb2
import authentication_pb2_grpc
from grpc_reflection.v1alpha import reflection


# Secret key for encoding and decoding the JWT. This is just for demo. In realworld, it must be stored in Secret management.
SECRET_KEY = os.environ['JWT_SECRET_KEY']

# Define DB URI template
URI_TEMPLATE = (
    "postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)

DATABASE_URL = URI_TEMPLATE.format(
    DB_USER = os.environ['DATABASE_USER'],
    DB_PASSWORD = os.environ['DATABASE_PASSWORD'],
    DB_HOST = os.environ['DATABASE_HOST'],
    DB_PORT = os.environ['DATABASE_PORT'],
    DB_NAME =os.environ['DATABASE_NAME']
)

# Database setup
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

# Define the base class for declarative models
Base = declarative_base()

# Define the User model
class User(Base):
    """User model representing the database 
    table for storing user information.
    """
    
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(256), unique=True, nullable=False)
    name = Column(String(256), nullable=False)
    password = Column(String(256), nullable=False)  # Store hashed password

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', name='{self.name}')>"

class AccessToken(Base):
    """AccessToken model representing the database table for storing access_tokens."""
    
    __tablename__ = 'access_tokens'

    username = Column(String(256), primary_key=True)  # 'username' as the primary key
    access_token = Column(String(512), nullable=False)  # Adjust length as needed

    def __repr__(self):
        return f"<AccessToken(username='{self.username}', access_token='{self.access_token}')>"

# Create tables in the database
Base.metadata.create_all(engine)

class AuthenticationService(authentication_pb2_grpc.AuthenticationServiceServicer):
    """gRPC service for user authentication."""

    def SignUp(self, request, context):
        """
        Handles user registration.

        Args:
            request: SignUpRequest containing the username, name, and password.
            context: gRPC context for setting response details and status codes.

        Returns:
            SignUpResponse containing user information if successful.
        """
        session = Session()
       
        try:
            # Check if username already exists
            existing_user = session.query(User).filter_by(username=request.username).first()
            if existing_user:
                context.set_details("Username already exists")
                context.set_code(grpc.StatusCode.ALREADY_EXISTS)
                return authentication_pb2.SignUpResponse()

            # Create new user with hashed password
            new_user = User(
                username=request.username,
                name=request.name,
                password=generate_password_hash(request.password)
            )
            
            # Add and commit the new user to the database
            session.add(new_user)
            session.commit()

            # Prepare response with the new user's information
            response_user = authentication_pb2.User(
                id=new_user.id,
                username=new_user.username,
                name=new_user.name
            )

            return authentication_pb2.SignUpResponse(user=response_user)

        except Exception as e:
            session.rollback()
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return authentication_pb2.SignUpResponse()

        finally:
            session.close()

    def Login(self, request, context):
        """
        Handles user login.

        Args:
            request: LoginRequest containing the username and password.
            context: gRPC context for setting response details and status codes.

        Returns:
            LoginResponse containing user information and an access token if successful.
        """
        session = Session()
      
        try:
            user = session.query(User).filter_by(username=request.username).first()
            if not user:
                context.set_details("User not found")
                context.set_code(grpc.StatusCode.NOT_FOUND)
                return authentication_pb2.LoginResponse()

            if not check_password_hash(user.password, request.password):
                context.set_details("Incorrect password")
                context.set_code(grpc.StatusCode.UNAUTHENTICATED)
                return authentication_pb2.LoginResponse()

            # Generate JWT
            expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)  # Token valid for 1 hour
            payload = {
                "sub": user.id,
                "exp": expiration_time,
                "username": user.username,
                "name": user.name,
            }
            
            access_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
        
            new_access_token = AccessToken(
                username=user.username,
                access_token=access_token
            )

            # push access token to the DB
            session.add(new_access_token)
            session.commit()

            user_data = authentication_pb2.User(
                id=user.id,
                username=user.username,
                name=user.name
            )

            return authentication_pb2.LoginResponse(user=user_data, access_token=access_token)

        except Exception as e:
            context.set_details(str(e))
            context.set_code(grpc.StatusCode.INTERNAL)
            return authentication_pb2.LoginResponse()

        finally:
            session.close()

def serve():
    """
    Starts the gRPC server to listen for requests.
    """

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    authentication_pb2_grpc.add_AuthenticationServiceServicer_to_server(AuthenticationService(), server)

    # Enable reflection on the server
    service_names = (
        authentication_pb2.DESCRIPTOR.services_by_name['AuthenticationService'].full_name,
        reflection.SERVICE_NAME,
    )

    reflection.enable_server_reflection(service_names, server)
    server.add_insecure_port('[::]:45000')
    server.start()
    print("Server is running on port 45000...")
    server.wait_for_termination()

if __name__ == '__main__':
    serve()
