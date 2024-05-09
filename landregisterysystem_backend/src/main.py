
from flask import Flask, request, jsonify
from candid import idl
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS


from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

from flask_sqlalchemy import SQLAlchemy

app= Flask (__name__)
CORS(app) #enable cors for all routes
from candid import (
    Nat,
    Int,
    Principal,
    Text,
    Bool,
    Opt,
    Vec,
    Record,
    Variant,
    Service,
    Func,
    Query,
)

SetPermissions = Record({
    'prepare': Vec(Principal),
    'commit': Vec(Principal),
    'manage_permissions': Vec(Principal),
})

UpgradeArgs = Record({
    'set_permissions': Opt(SetPermissions),
})

InitArgs = Record({})

AssetCanisterArgs = Variant({
    'Upgrade': UpgradeArgs,
    'Init': InitArgs,
})

ClearArguments = Record({})

BatchId = Nat
Key = Text
HeaderField = Record(Text, Text)

SetAssetPropertiesArguments = Record({
    'key': Key,
    'headers': Opt(Opt(Vec(HeaderField))),
    'is_aliased': Opt(Opt(Bool)),
    'allow_raw_access': Opt(Opt(Bool)),
    'max_age': Opt(Opt(Nat)),
})

CreateAssetArguments = Record({
    'key': Key,
    'content_type': Text,
    'headers': Opt(Vec(HeaderField)),
    'allow_raw_access': Opt(Bool),
    'max_age': Opt(Nat),
    'enable_aliasing': Opt(Bool),
})

UnsetAssetContentArguments = Record({
    'key': Key,
    'content_encoding': Text,
})

DeleteAssetArguments = Record({'key': Key})

ChunkId = Nat

SetAssetContentArguments = Record({
    'key': Key,
    'sha256': Opt(Vec(Nat)),
    'chunk_ids': Vec(ChunkId),
    'content_encoding': Text,
})

BatchOperationKind = Variant({
    'SetAssetProperties': SetAssetPropertiesArguments,
    'CreateAsset': CreateAssetArguments,
    'UnsetAssetContent': UnsetAssetContentArguments,
    'DeleteAsset': DeleteAssetArguments,
    'SetAssetContent': SetAssetContentArguments,
    'Clear': ClearArguments,
})

CommitBatchArguments = Record({
    'batch_id': BatchId,
    'operations': Vec(BatchOperationKind),
})

CommitProposedBatchArguments = Record({
    'batch_id': BatchId,
    'evidence': Vec(Nat),
})

ComputeEvidenceArguments = Record({
    'batch_id': BatchId,
    'max_iterations': Opt(Nat),
})

ConfigureArguments = Record({
    'max_batches': Opt(Opt(Nat)),
    'max_bytes': Opt(Opt(Nat)),
    'max_chunks': Opt(Opt(Nat)),
})

DeleteBatchArguments = Record({'batch_id': BatchId})

ConfigurationResponse = Record({
    'max_batches': Opt(Nat),
    'max_bytes': Opt(Nat),
    'max_chunks': Opt(Nat),
})

Permission = Variant({
    'Prepare': None,
    'ManagePermissions': None,
    'Commit': None,
})

GrantPermission = Record({
    'permission': Permission,
    'to_principal': Principal,
})

HttpRequest = Record({
    'url': Text,
    'method': Text,
    'body': Vec(Nat),
    'headers': Vec(HeaderField),
    'certificate_version': Opt(Nat),
})

StreamingCallbackToken = Record({
    'key': Key,
    'sha256': Opt(Vec(Nat)),
    'index': Nat,
    'content_encoding': Text,
})

StreamingCallbackHttpResponse = Record({
    'token': Opt(StreamingCallbackToken),
    'body': Vec(Nat),
})

StreamingStrategy = Variant({
    'Callback': Record({
        'token': StreamingCallbackToken,
        'callback': Func([StreamingCallbackToken], [Opt(StreamingCallbackHttpResponse)], [Query]),
    }),
})

HttpResponse = Record({
    'body': Vec(Nat),
    'headers': Vec(HeaderField),
    'streaming_strategy': Opt(StreamingStrategy),
    'status_code': Nat,
})

Time = Int

ListPermitted = Record({'permission': Permission})

RevokePermission = Record({
    'permission': Permission,
    'of_principal': Principal,
})

ValidationResult = Variant({'Ok': Text, 'Err': Text})

# Define the service
service = Service({
    'api_version': Func([], [Nat], [Query]),
    'authorize': Func([Principal], [], []),
    'certified_tree': Func([Record({})], [Record({'certificate': Vec(Nat), 'tree': Vec(Nat)})], [Query]),
    'clear': Func([ClearArguments], [], []),
    'commit_batch': Func([CommitBatchArguments], [], []),
    'commit_proposed_batch': Func([CommitProposedBatchArguments], [], []),
    'compute_evidence': Func([ComputeEvidenceArguments], [Opt(Vec(Nat))], []),
    'configure': Func([ConfigureArguments], [], []),
    'create_asset': Func([CreateAssetArguments], [], []),
    'create_batch': Func([Record({})], [Record({'batch_id': BatchId})], []),
    'create_chunk': Func([Record({'content': Vec(Nat), 'batch_id': BatchId})], [Record({'chunk_id': ChunkId})], []),
    'deauthorize': Func([Principal], [], []),
    'delete_asset': Func([DeleteAssetArguments], [], []),
    'delete_batch': Func([DeleteBatchArguments], [], []),
    'get': Func([Record({'key': Key, 'accept_encodings': Vec(Text)})], [
        Record({
            'content': Vec(Nat),
            'sha256': Opt(Vec(Nat)),
            'content_type': Text,
            'content_encoding': Text,
            'total_length': Nat,
        }),
    ], [Query]),
    'get_asset_properties': Func([Key], [
        Record({
            'headers': Opt(Vec(HeaderField)),
            'is_aliased': Opt(Bool),
            'allow_raw_access': Opt(Bool),
            'max_age': Opt(Nat),
        }),
    ], [Query]),
    'get_chunk': Func([Record({'key': Key, 'sha256': Opt(Vec(Nat)), 'index': Nat, 'content_encoding': Text})], [
        Record({'content': Vec(Nat)}),
    ], [Query]),
    'get_configuration': Func([], [ConfigurationResponse], []),
    'grant_permission': Func([GrantPermission], [], []),
    'http_request': Func([HttpRequest], [HttpResponse], [Query]),
    'http_request_streaming_callback': Func([StreamingCallbackToken], [Opt(StreamingCallbackHttpResponse)], [Query]),
    'list': Func([Record({})], [
        Vec(
            Record({
                'key': Key,
                'encodings': Vec(
                    Record({
                        'modified': Time,
                        'sha256': Opt(Vec(Nat)),
                        'length': Nat,
                        'content_encoding': Text,
                    })
                ),
                'content_type': Text,
            })
        ),
    ], [Query]),
    'list_authorized': Func([], [Vec(Principal)], []),
    'list_permitted': Func([ListPermitted], [Vec(Principal)], []),
    'propose_commit_batch': Func([CommitBatchArguments], [], []),
    'revoke_permission': Func([RevokePermission], [], []),
    'set_asset_content': Func([SetAssetContentArguments], [], []),
    'set_asset_properties': Func([SetAssetPropertiesArguments], [], []),
    'store': Func([Record({
        'key': Key,
        'content': Vec(Nat),
        'sha256': Opt(Vec(Nat)),
        'content_type': Text,
        'content_encoding': Text,
    })], [], []),
    'take_ownership': Func([], [], []),
    'unset_asset_content': Func([UnsetAssetContentArguments], [], []),
    'validate_commit_proposed_batch': Func([CommitProposedBatchArguments], [ValidationResult], []),
    'validate_configure': Func([ConfigureArguments], [ValidationResult], []),
    'validate_grant_permission': Func([GrantPermission], [ValidationResult], []),
    'validate_revoke_permission': Func([RevokePermission], [ValidationResult], []),
    'validate_take_ownership': Func([], [ValidationResult], []),
})



# Initialize Flask application
app = Flask(__name__)

# Define Candid IDL types


# Define backend routes

# Example route to handle HTTP POST request from frontend
@app.route('/api/submit_data', methods=['POST'])
def submit_data():
    data = request.json  # Assuming JSON data is sent from frontend

    # Process the received data, perform backend logic, etc.

    # Return response to frontend
    return jsonify({"message": "Data received successfully"})

# Example route to handle other types of requests

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
db = SQLAlchemy(app)

class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_key = db.Column(db.String(100))
    data_value = db.Column(db.String(100))


@app.route('/api/store-data', methods=['POST'])
def store_data():
    data = request.json
    data_key = data.get('key')
    data_value = data.get('value')

    new_data_entry = Data(data_key=data_key, data_value=data_value)
    db.session.add(new_data_entry)
    db.session.commit()

    return jsonify({'message': 'Data stored successfully'})

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)


app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///land_registry.db'
db = SQLAlchemy(app)

# Define database models
class Parcel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parcel_of_land = db.Column(db.String(100))
    description = db.Column(db.String(255))
    coordinates = db.Column(db.String(255))

class Owner(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    owner_type = db.Column(db.String(100))
    contact_info = db.Column(db.String(100))
    other_details = db.Column(db.String(255))

# Define API endpoints
@app.route('/parcels', methods=['GET'])
def get_parcels():
    parcels = Parcel.query.all()
    return jsonify([{
        'id': parcel.id,
        'parcel_of_land': parcel.parcel_of_land,
        'description': parcel.description,
        'coordinates': parcel.coordinates
    } for parcel in parcels])

@app.route('/owners', methods=['GET'])
def get_owners():
    owners = Owner.query.all()
    return jsonify([{
        'id': owner.id,
        'name': owner.name,
        'owner_type': owner.owner_type,
        'contact_info': owner.contact_info,
        'other_details': owner.other_details
    } for owner in owners])

# Add more API endpoints for CRUD operations as needed

if __name__ == '__main__':
    db.create_all()  # Create database tables
    app.run(debug=True)

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///land_registry.db'
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Change this to a strong random secret key
app.config['JWT_SECRET_KEY'] = 'jwt_secret_key'  # Change this to a strong random JWT secret key
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Define database models (Parcel, Owner, etc.) and API endpoints as before...

# Authentication endpoint
@app.route('/login', methods=['POST'])
def login():
    from flask import User  # Replace "your_module" with the actual module name where the User class is defined

    username = request.json.get('username')
    password = request.json.get('password')

    # Check if username and password are provided
    if not username or not password:
        return jsonify({'message': 'Missing username or password'}), 400

    # Check if user exists in the database
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    # Generate JWT token for authentication
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

# Protected endpoint example
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Adding  API endpoints and authentication/authorization logic as needed...