from django.test import TestCase
from rest_framework import reverse
from rest_framework.test import APITestCase
from django.contrib.auth.models import User
from rest_framework import status

# Create your tests here.

class AccountTest(APITestCase):
    def set_up(self):
        self.test_user = User.objects.create_user('admin', 'admin@gmail.com', 'admin@1234')
        # URL for creating an account.
        self.create_url = reverse.reverse('account-create')

    def test_create_user(self):
        """
        Ensure we can create a new user and a valid token is created with it.
        """
        data = {
            'username': 'admin',
            'email': 'admin@gmail.com',
            'password': 'admin@1234'
        }

        response = self.client.post(self.create_url, data, format='json')

        # We want to make sure we have two users in the database..
        self.assertEqual(User.objects.count(), 2)
        # And that we're returning a 201 created code.
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # Additionally, we want to return the username and email upon successful creation.
        self.assertEqual(response.data['username'], data['username'])
        self.assertEqual(response.data['email'], data['email'])
        self.assertFalse('password' in response.data)
