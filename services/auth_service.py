from odoo import api, SUPERUSER_ID
from odoo.exceptions import UserError


class AuthService:

    @staticmethod
    def get_user_info(user):

        return {
            'id': user.id,
            'name': user.name,
            'login': user.login,
            'email': user.email,
        }

    @staticmethod
    def create_portal_user(env, name, email, password):

        Users = env['res.users'].sudo()

        existing_user = Users.search([
            '|',
            ('login', '=ilike', email),
            ('email', '=ilike', email),
        ], limit=1)

        if existing_user:
            raise UserError('An account with this email already exists.')

        portal_group = env.ref('base.group_portal')

        user = Users.with_context(
            no_reset_password=True
        ).create({
            'name': name,
            'login': email,
            'email': email,
            'password': password,
            'group_ids': [(6, 0, [portal_group.id])],
        })

        return user