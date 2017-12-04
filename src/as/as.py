from access_token import Token
from flask import Flask, jsonify, request
from jwcrypto import jwk

CRYPTO_KEY = '123456789'
SIGNATURE_KEY = '723984572'


class Client:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret


# Verifies that
def verify_token_request():
    expected_keys = ['grant_type',
                     'client_id',
                     'client_secret',
                     'aud']

    if request.get_json() is None:
        return False

    return all(key in request.get_json() for key in expected_keys)


def verify_client(client_id, client_secret):
    is_registered = client_id in [c.client_id for c in approved_clients]

    if is_registered:
        registered_secret = [c.client_secret for c in approved_clients if c.client_id == client_id][0]

        if registered_secret == client_secret:
            return True

    return False


app = Flask(__name__)
approved_clients = [Client("123456789", "verysecret")]


# Clients endpoint
#
# Returns a list of all approved client IDs.
# ONLY FOR DEBUGGING PURPOSES
@app.route("/clients")
def clients():
    return jsonify({'approved_clients': [c.client_id for c in approved_clients]})


# Token endpoint
#
# Validates the incoming requests and grants an access token if valid. Must be POST [ACE 5.6.1]
# Returns error codes as stated in [ACE 5.6.3]
@app.route("/token", methods=['POST'])
def token():
    # Verify basic request
    if not verify_token_request():
        return jsonify({'error': 'invalid_request'}), 400

    params = request.get_json()

    client_id = params['client_id']
    client_secret = params['client_secret']

    # Check if client is registered
    if not verify_client(client_id, client_secret):
        return jsonify({'error': 'unauthorized_client'}), 400

    # Extract Clients Public key
    client_pk = jwk.JWK()
    client_pk.import_key(**params['cnf']['jwk'])

    # Issue Token
    tkn = Token.make_token(client_pk, SIGNATURE_KEY, CRYPTO_KEY)

    return jsonify(tkn)


def main():
    app.run(port=8080)


if __name__ == "__main__":
    main()
