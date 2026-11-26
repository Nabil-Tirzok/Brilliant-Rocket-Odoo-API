import logging
import secrets
from html import escape
from urllib.parse import urlparse, parse_qs

from odoo import http, fields
from odoo.http import request
from odoo.exceptions import AccessDenied, UserError

from ..services.auth_service import AuthService


_logger = logging.getLogger(__name__)


class AuthController(http.Controller):

    # --------------------------------------------------
    # LOGIN
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/login',
        type='http',
        auth='public',
        methods=['POST'],
        csrf=False
    )
    def login(self, **kwargs):

        data = request.httprequest.get_json(silent=True) or {}

        login = data.get('login')
        password = data.get('password')

        if not login or not password:
            return request.make_json_response({
                'success': False,
                'message': 'Email and password are required.'
            }, status=400)

        try:

            credential = {
                'login': login,
                'password': password,
                'type': 'password',
            }

            request.session.authenticate(
                request.env,
                credential
            )

            user = request.env['res.users'].sudo().browse(
                request.session.uid
            )

            return request.make_json_response({
                'success': True,
                'message': 'Login successful.',
                'data': {
                    'user': AuthService.get_user_info(user)
                }
            })

        except AccessDenied:

            return request.make_json_response({
                'success': False,
                'message': 'Invalid email or password.'
            }, status=401)

    # --------------------------------------------------
    # REGISTRATION
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/register',
        type='http',
        auth='public',
        methods=['POST'],
        csrf=False,
    )
    def register(self, **kwargs):

        data = request.httprequest.get_json(silent=True) or {}

        name = (data.get('name') or '').strip()
        email = (data.get('email') or '').strip().lower()
        password = data.get('password') or ''

        if not name or not email or not password:
            return request.make_json_response({
                'success': False,
                'message': 'Name, email and password are required.',
            }, status=400)

        if len(name) > 150 or len(email) > 254:
            return request.make_json_response({
                'success': False,
                'message': 'Name or email is too long.',
            }, status=400)

        if '@' not in email:
            return request.make_json_response({
                'success': False,
                'message': 'Please provide a valid email address.',
            }, status=400)

        if len(password) < 12:
            return request.make_json_response({
                'success': False,
                'message': 'Password must contain at least 12 characters.',
            }, status=400)

        try:

            Registration = request.env[
                'brilliant.rocket.registration'
            ].sudo()

            Users = request.env['res.users'].sudo().with_context(
                active_test=False
            )

            # --------------------------------------------------
            # CHECK EXISTING REGISTRATION
            # --------------------------------------------------

            registration = Registration.search([
                ('email', '=ilike', email),
            ], limit=1, order='id desc')

            if registration:

                # Already verified
                if registration.verified:
                    return request.make_json_response({
                        'success': False,
                        'message': (
                            'An account with this email already exists. '
                            'Please log in.'
                        ),
                    }, status=409)

                # --------------------------------------------------
                # EXISTING PENDING REGISTRATION
                # --------------------------------------------------

                # Preserve the original user, name and password.
                user = registration.user_id

                if not user.exists():
                    return request.make_json_response({
                        'success': False,
                        'message': (
                            'Pending registration could not be found. '
                            'Please contact support.'
                        ),
                    }, status=409)

                # Generate fresh tokens.
                verification_token = secrets.token_urlsafe(32)
                status_token = secrets.token_urlsafe(32)

                # Update the existing registration.
                registration.write({
                    'verification_token_hash': Registration.hash_token(
                        verification_token
                    ),
                    'status_token_hash': Registration.hash_token(
                        status_token
                    ),
                    'expiration': fields.Datetime.add(
                        fields.Datetime.now(),
                        hours=24,
                    ),
                })

                # Keep the account inactive until verification.
                user.sudo().write({
                    'active': False,
                })

                registration_name = registration.name

                _logger.info(
                    'Resending verification email for pending registration: %s',
                    email,
                )

            else:

                # --------------------------------------------------
                # CHECK EXISTING USER
                # --------------------------------------------------

                existing_user = Users.search([
                    '|',
                    ('login', '=ilike', email),
                    ('email', '=ilike', email),
                ], limit=1)

                if existing_user:
                    return request.make_json_response({
                        'success': False,
                        'message': (
                            'An account with this email already exists. '
                            'Please log in.'
                        ),
                    }, status=409)

                # --------------------------------------------------
                # NEW REGISTRATION
                # --------------------------------------------------

                user = AuthService.create_portal_user(
                    request.env,
                    name,
                    email,
                    password,
                )

                # Account remains inactive until verification.
                user.sudo().write({
                    'active': False,
                })

                registration, verification_token, status_token = (
                    Registration.create_registration(
                        name,
                        email,
                        user,
                    )
                )

                registration_name = name

                _logger.info(
                    'New registration created for: %s',
                    email,
                )

            # --------------------------------------------------
            # SEND VERIFICATION EMAIL
            # --------------------------------------------------

            base_url = request.env[
                'ir.config_parameter'
            ].sudo().get_param('web.base.url')

            verification_link = (
                f'{base_url}/api/v1/auth/verify-email'
                f'?token={verification_token}'
            )

            mail = request.env['mail.mail'].sudo().create({
                'subject': 'Verify your Brilliant Rocket account',
                'email_from': 'Brilliant Rocket <rafidnabil3@gmail.com>',
                'email_to': email,
                'body_html': f"""
                    <div>
                        <h2>Verify your email address</h2>

                        <p>Hello {escape(registration_name)},</p>

                        <p>
                            Thank you for registering with Brilliant Rocket.
                            Click the button below to verify your email
                            address.
                        </p>

                        <p>
                            <a href="{escape(verification_link, quote=True)}"
                               style="
                                   display: inline-block;
                                   padding: 12px 24px;
                                   background-color: #2563eb;
                                   color: white;
                                   text-decoration: none;
                                   border-radius: 6px;
                               ">
                                Verify Email
                            </a>
                        </p>

                        <p>
                            This link expires in 24 hours.
                        </p>

                        <p>
                            If you did not request this account,
                            you can ignore this email.
                        </p>
                    </div>
                """,
            })

            mail.send()

            if mail.state == 'exception':
                _logger.error(
                    'Verification email failed for %s: %s',
                    email,
                    mail.failure_reason,
                )

                return request.make_json_response({
                    'success': False,
                    'message': 'Unable to send the verification email.',
                }, status=500)

            return request.make_json_response({
                'success': True,
                'message': 'Verification link sent to your email.',
                'data': {
                    'email': email,
                    'status_token': status_token,
                    'verification_pending': True,
                },
            }, status=200)

        except Exception:

            _logger.exception('Registration error')

            return request.make_json_response({
                'success': False,
                'message': 'Unable to process registration.',
            }, status=500)

    # --------------------------------------------------
    # VERIFY EMAIL LINK (GET)
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/verify-email',
        type='http',
        auth='public',
        methods=['GET'],
        csrf=False,
    )
    def verify_email_link(self, **kwargs):

        token = kwargs.get('token')

        if not token:
            return request.make_response(
                '<h2>Invalid verification link.</h2>',
                headers=[('Content-Type', 'text/html')],
                status=400,
            )

        Registration = request.env[
            'brilliant.rocket.registration'
        ].sudo()

        registration = Registration.search([
            (
                'verification_token_hash',
                '=',
                Registration.hash_token(token),
            ),
        ], limit=1)

        if not registration:

            return request.make_response(
                '<h2>This verification link is invalid or has expired.</h2>',
                headers=[('Content-Type', 'text/html')],
                status=400,
            )

        if registration.verified:

            return request.make_response(
                """
                <html>
                    <body style="font-family: Arial; text-align: center; padding: 50px;">
                        <h1>Email already verified!</h1>
                        <p>Your Brilliant Rocket account has already been verified.</p>
                        <p>You can return to the mobile app.</p>
                    </body>
                </html>
                """,
                headers=[('Content-Type', 'text/html')],
                status=200,
            )

        if not registration.verify_link_token(token):

            return request.make_response(
                '<h2>This verification link is invalid or has expired.</h2>',
                headers=[('Content-Type', 'text/html')],
                status=400,
            )

        return request.make_response(
            """
            <html>
                <body style="font-family: Arial; text-align: center; padding: 50px;">
                    <h1>Email verified successfully!</h1>
                    <p>Your Brilliant Rocket account has been verified.</p>
                    <p>You can now return to the mobile app.</p>
                </body>
            </html>
            """,
            headers=[('Content-Type', 'text/html')],
            status=200,
        )

    # --------------------------------------------------
    # VERIFICATION STATUS
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/verification-status',
        type='http',
        auth='public',
        methods=['POST'],
        csrf=False,
    )
    def verification_status(self, **kwargs):

        data = request.httprequest.get_json(silent=True) or {}

        email = (data.get('email') or '').strip().lower()
        status_token = data.get('status_token') or ''

        if not email or not status_token:
            return request.make_json_response({
                'success': False,
                'message': 'Email and status token are required.',
            }, status=400)

        Registration = request.env[
            'brilliant.rocket.registration'
        ].sudo()

        registration = Registration.search([
            ('email', '=ilike', email),
        ], limit=1, order='id desc')

        if not registration or not registration.check_status_token(
            status_token
        ):
            return request.make_json_response({
                'success': False,
                'message': 'Invalid registration details.',
            }, status=401)

        if registration.verified:
            return request.make_json_response({
                'success': True,
                'verified': True,
                'message': 'Email verified successfully.',
            })

        if fields.Datetime.now() > registration.expiration:
            return request.make_json_response({
                'success': False,
                'verified': False,
                'message': 'Verification link has expired.',
            }, status=400)

        return request.make_json_response({
            'success': True,
            'verified': False,
            'message': 'Email has not been verified yet.',
        })

    # --------------------------------------------------
    # EMAIL VERIFICATION (OTP)
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/verify-email',
        type='http',
        auth='public',
        methods=['POST'],
        csrf=False
    )
    def verify_email(self, **kwargs):

        data = request.httprequest.get_json(silent=True) or {}

        email = (data.get('email') or '').strip().lower()
        otp = str(data.get('otp') or '')
        password = data.get('password')

        if not email or len(otp) != 6 or not otp.isdigit() or not password:
            return request.make_json_response({
                'success': False,
                'message': 'Invalid verification information.'
            }, status=400)

        if len(password) < 12:
            return request.make_json_response({
                'success': False,
                'message': 'Password must be at least 12 characters.'
            }, status=400)

        try:

            Registration = request.env[
                'brilliant.rocket.registration'
            ].sudo()

            registration = Registration.search([
                ('email', '=ilike', email)
            ], limit=1, order='id desc')

            if not registration:
                return request.make_json_response({
                    'success': False,
                    'message': 'Invalid or expired verification code.'
                }, status=400)

            if not registration.verify_otp(otp):
                return request.make_json_response({
                    'success': False,
                    'message': 'Invalid or expired verification code.'
                }, status=400)

            user = AuthService.create_portal_user(
                request.env,
                registration.name,
                registration.email,
                password
            )

            registration.unlink()

            return request.make_json_response({
                'success': True,
                'message': 'Registration completed successfully.',
                'data': {
                    'user': AuthService.get_user_info(user)
                }
            }, status=201)

        except UserError as error:

            return request.make_json_response({
                'success': False,
                'message': str(error)
            }, status=400)

        except Exception:

            _logger.exception('Email verification error')

            return request.make_json_response({
                'success': False,
                'message': 'Unable to complete registration.'
            }, status=500)

    # --------------------------------------------------
    # FORGOT PASSWORD
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/forgot-password',
        type='http',
        auth='public',
        methods=['POST'],
        csrf=False,
    )
    def forgot_password(self, **kwargs):

        data = request.httprequest.get_json(silent=True) or {}

        email = (data.get('email') or '').strip().lower()

        if not email:
            return request.make_json_response({
                'success': False,
                'message': 'Email is required.',
            }, status=400)

        generic_response = {
            'success': True,
            'message': (
                'If an account exists for this email, '
                'password reset instructions will be sent.'
            ),
        }

        try:
            Users = request.env['res.users'].sudo()

            users = Users.search([
                ('active', '=', True),
                '|',
                ('login', '=ilike', email),
                ('email', '=ilike', email),
            ], limit=2)

            # Do not reveal whether an account exists.
            if len(users) != 1:
                return request.make_json_response(generic_response)

            user = users

            if not user.partner_id or not user.email:
                return request.make_json_response(generic_response)

            partner = user.partner_id.sudo()

            # --------------------------------------------------
            # GENERATE PASSWORD RESET TOKEN
            # --------------------------------------------------

            partner.signup_cancel()
            partner.signup_prepare(signup_type='reset')

            # Extract the raw token from Odoo's generated signup URL.
            signup_url = partner._get_signup_url()

            if not signup_url:
                raise ValueError(
                    'Failed to generate password reset URL.'
                )

            parsed_url = urlparse(signup_url)
            token = parse_qs(parsed_url.query).get(
                'token',
                [None],
            )[0]

            if not token:
                raise ValueError(
                    'Failed to extract password reset token.'
                )


            # --------------------------------------------------
            # FLUTTER DEEP LINK
            # --------------------------------------------------

            reset_link = (
                'brilliantrocket://reset-password'
                f'?token={token}'
            )

            # --------------------------------------------------
            # SEND PASSWORD RESET EMAIL
            # --------------------------------------------------

            mail = request.env['mail.mail'].sudo().create({
                'subject': 'Reset your Brilliant Rocket password',
                'email_from': (
                    'Brilliant Rocket <rafidnabil3@gmail.com>'
                ),
                'email_to': user.email,
                'body_html': f"""
                    <div>
                        <h2>Password Reset</h2>

                        <p>Hello {escape(user.name or 'User')},</p>

                        <p>
                            We received a request to reset your
                            Brilliant Rocket account password.
                        </p>

                        <p>
                            Click the button below to continue
                            in the mobile application.
                        </p>

                        <p>
                            <a href="{escape(reset_link, quote=True)}"
                               style="
                                   display: inline-block;
                                   padding: 12px 24px;
                                   background-color: #2563eb;
                                   color: white;
                                   text-decoration: none;
                                   border-radius: 6px;
                               ">
                                Reset Password
                            </a>
                        </p>

                        <p>
                            If you did not request a password reset,
                            you can ignore this email.
                        </p>
                    </div>
                """,
            })

            mail.send()

            if mail.state == 'exception':
                _logger.error(
                    'Password reset email failed for %s: %s',
                    email,
                    mail.failure_reason,
                )

        except Exception:
            _logger.exception(
                'Password reset request failed for %s',
                email,
            )

        return request.make_json_response(generic_response)

    # --------------------------------------------------
    # RESET PASSWORD
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/reset-password',
        type='http',
        auth='public',
        methods=['POST'],
        csrf=False,
    )
    def reset_password(self, **kwargs):

        data = request.httprequest.get_json(silent=True) or {}

        token = (data.get('token') or '').strip()
        new_password = data.get('new_password') or ''
        confirm_password = data.get('confirm_password') or ''

        # --------------------------------------------------
        # VALIDATE INPUT
        # --------------------------------------------------

        if not token or not new_password or not confirm_password:
            return request.make_json_response({
                'success': False,
                'message': (
                    'Token, new password and password confirmation '
                    'are required.'
                ),
            }, status=400)

        if len(new_password) < 12:
            return request.make_json_response({
                'success': False,
                'message': 'Password must contain at least 12 characters.',
            }, status=400)

        if new_password != confirm_password:
            return request.make_json_response({
                'success': False,
                'message': 'Passwords do not match.',
            }, status=400)

        try:

            # --------------------------------------------------
            # VALIDATE RESET TOKEN
            # --------------------------------------------------

            Partner = request.env['res.partner'].sudo()

            partner = Partner._signup_retrieve_partner(
                token,
                check_validity=True,
                raise_exception=True,
            )

            # Only accept password-reset tokens.
            if partner.signup_type != 'reset':
                return request.make_json_response({
                    'success': False,
                    'message': 'Invalid password reset token.',
                }, status=400)

            # --------------------------------------------------
            # UPDATE PASSWORD
            # --------------------------------------------------

            request.env['res.users'].sudo().signup(
                {
                    'password': new_password,
                },
                token=token,
            )

            return request.make_json_response({
                'success': True,
                'message': 'Your password has been reset successfully.',
            })

        except Exception:

            _logger.exception('Password reset failed')

            return request.make_json_response({
                'success': False,
                'message': (
                    'The password reset link is invalid or has expired. '
                    'Please request a new one.'
                ),
            }, status=400)

    # --------------------------------------------------
    # LOGOUT
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/logout',
        type='http',
        auth='user',
        methods=['POST'],
        csrf=False
    )
    def logout(self, **kwargs):

        request.session.logout(keep_db=True)

        return request.make_json_response({
            'success': True,
            'message': 'Logged out successfully.'
        })

    # --------------------------------------------------
    # CURRENT USER
    # --------------------------------------------------

    @http.route(
        '/api/v1/auth/me',
        type='http',
        auth='user',
        methods=['GET']
    )
    def me(self, **kwargs):

        user = request.env.user

        return request.make_json_response({
            'success': True,
            'data': {
                'user': AuthService.get_user_info(user)
            }
        })