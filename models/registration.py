import hashlib
import hmac
import secrets

from odoo import api, fields, models


class BrilliantRocketRegistration(models.Model):
    _name = 'brilliant.rocket.registration'
    _description = 'Brilliant Rocket Pending Registration'

    name = fields.Char(required=True)
    email = fields.Char(required=True, index=True)
    user_id = fields.Many2one(
        'res.users',
        required=True,
        ondelete='cascade',
    )

    verification_token_hash = fields.Char(required=True)
    status_token_hash = fields.Char(required=True)
    expiration = fields.Datetime(required=True)

    verified = fields.Boolean(default=False)

    @staticmethod
    def hash_token(token):
        return hashlib.sha256(token.encode('utf-8')).hexdigest()

    @api.model
    def create_registration(self, name, email, user):
        verification_token = secrets.token_urlsafe(32)

        status_token = secrets.token_urlsafe(32)

        registration = self.create({
            'name': name,
            'email': email,
            'user_id': user.id,
            'verification_token_hash': self.hash_token(
                verification_token
            ),
            'status_token_hash': self.hash_token(status_token),
            'expiration': fields.Datetime.add(
                fields.Datetime.now(),
                hours=24,
            ),
        })

        return registration, verification_token, status_token

    def verify_link_token(self, token):
        self.ensure_one()

        if self.verified:
            return True

        if fields.Datetime.now() > self.expiration:
            return False

        submitted_hash = self.hash_token(token)

        if not hmac.compare_digest(
            submitted_hash,
            self.verification_token_hash,
        ):
            return False

        self.write({'verified': True})

        self.user_id.sudo().write({'active': True})

        return True

    def check_status_token(self, token):
        self.ensure_one()

        if not token:
            return False

        submitted_hash = self.hash_token(token)

        return hmac.compare_digest(
            submitted_hash,
            self.status_token_hash,
        )