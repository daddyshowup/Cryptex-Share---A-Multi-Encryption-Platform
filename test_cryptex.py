import unittest
import tempfile
import os
import shutil
import json
import time
import base64
import pickle
import sqlite3

# Import your tool's classes – adjust if your main file has a different name
from Cryptex_Share import (
    Database, UserManager, SecurityMonitor, SymmetricCrypto,
    AsymmetricCrypto, HashUtils, HybridCrypto, FileCrypto, FileSharingManager
)


class TestDatabase(unittest.TestCase):
    """Test the Database wrapper class."""
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        self.db = Database(self.temp_db.name)
        self.conn = sqlite3.connect(self.temp_db.name)

    def tearDown(self):
        self.conn.close()
        os.unlink(self.temp_db.name)

    def test_init_creates_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        self.assertIn('users', tables)
        self.assertIn('user_operations', tables)

    def test_execute_query_and_fetch(self):
        self.db.execute_query(
            "INSERT INTO users (email, username, password_hash, salt, created_at) VALUES (?,?,?,?,?)",
            ('test@ex.com', 'tester', 'hash', 'salt', 12345)
        )
        result = self.db.fetch_one("SELECT email FROM users WHERE email=?", ('test@ex.com',))
        self.assertEqual(result[0], 'test@ex.com')
        all_rows = self.db.fetch_all("SELECT email FROM users")
        self.assertEqual(len(all_rows), 1)


class TestUserManager(unittest.TestCase):
    """Test user registration, login, admin functions, lockout."""
    def setUp(self):
        # Use a temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(delete=False)
        self.temp_db.close()
        self.um = UserManager(self.temp_db.name)
        # Clear the users table to avoid duplicate admin
        self.um.db.execute_query("DELETE FROM users")
        self.um.db.execute_query("DELETE FROM user_operations")
        # Let the admin be created again (or skip if not needed)
        self.um._create_default_admin()   # ensure default admin exists

    def tearDown(self):
        os.unlink(self.temp_db.name)

    def test_register_success(self):
        ok, msg = self.um.register('new@user.com', 'newuser', 'Pass1234', 'Pass1234')
        self.assertTrue(ok)
        self.assertIn('successful', msg)
        user = self.um.get_user_by_email('new@user.com')
        self.assertIsNotNone(user)
        self.assertEqual(user['username'], 'newuser')
        self.assertFalse(user['is_admin'])

    def test_register_password_mismatch(self):
        ok, msg = self.um.register('a@b.com', 'u', 'pass', 'different')
        self.assertFalse(ok)
        self.assertEqual(msg, 'Passwords do not match')

    def test_register_short_password(self):
        ok, msg = self.um.register('a@b.com', 'u', 'short', 'short')
        self.assertFalse(ok)
        self.assertEqual(msg, 'Password must be at least 8 characters')

    def test_register_invalid_email(self):
        ok, msg = self.um.register('notanemail', 'u', 'Password1', 'Password1')
        self.assertFalse(ok)
        self.assertEqual(msg, 'Invalid email format')

    def test_register_existing_user(self):
        self.um.register('existing@ex.com', 'exist', 'Pass1234', 'Pass1234')
        ok, msg = self.um.register('existing@ex.com', 'other', 'Pass1234', 'Pass1234')
        self.assertFalse(ok)
        self.assertEqual(msg, 'User already exists')

    def test_login_success(self):
        self.um.register('test@ex.com', 'tester', 'Password1', 'Password1')
        ok, msg = self.um.login('test@ex.com', 'Password1')
        self.assertTrue(ok)
        self.assertEqual(self.um.current_user['email'], 'test@ex.com')
        self.assertEqual(self.um.current_user['username'], 'tester')

    def test_login_wrong_password(self):
        self.um.register('test@ex.com', 'tester', 'Password1', 'Password1')
        ok, msg = self.um.login('test@ex.com', 'wrong')
        self.assertFalse(ok)
        self.assertIn('attempts remaining', msg)

    def test_login_lockout(self):
        self.um.register('lock@me.com', 'lock', 'Pass1234', 'Pass1234')
        for _ in range(3):
            self.um.login('lock@me.com', 'wrong')
        ok, msg = self.um.login('lock@me.com', 'wrong')
        self.assertFalse(ok)
        self.assertIn('locked', msg.lower())

    def test_admin_functions(self):
        self.um.register('u1@ex.com', 'u1', 'Pass1234', 'Pass1234')
        # promote
        ok, msg = self.um.promote_to_admin('u1@ex.com')
        self.assertTrue(ok)
        user = self.um.get_user_by_email('u1@ex.com')
        self.assertTrue(user['is_admin'])
        # demote
        ok, msg = self.um.demote_from_admin('u1@ex.com')
        self.assertTrue(ok)
        user = self.um.get_user_by_email('u1@ex.com')
        self.assertFalse(user['is_admin'])
        # cannot demote main admin
        ok, msg = self.um.demote_from_admin('admin@encryption.suite')
        self.assertFalse(ok)
        # delete user
        ok, msg = self.um.delete_user('u1@ex.com')
        self.assertTrue(ok)
        self.assertIsNone(self.um.get_user_by_email('u1@ex.com'))

    def test_update_user_operation(self):
        self.um.register('op@ex.com', 'op', 'Pass1234', 'Pass1234')
        self.um.update_user_operation('op@ex.com', 'symmetric')
        ops = self.um.get_user_by_email('op@ex.com')['encryption_operations']
        self.assertEqual(ops['symmetric'], 1)


class TestSecurityMonitor(unittest.TestCase):
    """Test logging and statistics."""
    def setUp(self):
        self.temp_log = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        self.temp_log.close()
        self.sm = SecurityMonitor(self.temp_log.name)

    def tearDown(self):
        os.unlink(self.temp_log.name)

    def test_log_and_stats(self):
        self.sm.log_event('failed_login', {'user': 'a'})
        self.sm.log_event('successful_login', {'user': 'b'})
        self.sm.log_event('failed_decrypt', {'error': 'bad key'})
        self.sm.log_event('brute_force', {'ip': '1.2.3.4'})
        stats = self.sm.get_security_stats()
        self.assertEqual(stats['failed_logins'], 1)
        self.assertEqual(stats['successful_logins'], 1)
        self.assertEqual(stats['failed_decrypts'], 1)
        self.assertEqual(stats['brute_force_attempts'], 1)
        self.assertEqual(stats['attack_types']['brute_force'], 1)

    def test_stats_with_empty_log(self):
        stats = self.sm.get_security_stats()
        self.assertEqual(stats['failed_logins'], 0)


class TestSymmetricCrypto(unittest.TestCase):
    """Test symmetric encryption/decryption."""
    def test_generate_key_iv(self):
        for algo in ['AES', 'DES', '3DES', 'ChaCha20']:
            key, iv = SymmetricCrypto.generate_key_iv(algo)
            self.assertIsInstance(key, bytes)
            self.assertIsInstance(iv, bytes)

    def test_encrypt_decrypt_aes_cbc(self):
        key, iv = SymmetricCrypto.generate_key_iv('AES')
        plain = 'Hello, world!'
        cipher = SymmetricCrypto.encrypt_text('AES', 'CBC', plain, key, iv)
        decrypted = SymmetricCrypto.decrypt_text('AES', 'CBC', cipher, key, iv)
        self.assertEqual(plain, decrypted)

    def test_encrypt_decrypt_aes_gcm(self):
        key, iv = SymmetricCrypto.generate_key_iv('AES')
        plain = 'Secret message'
        cipher = SymmetricCrypto.encrypt_text('AES', 'GCM', plain, key, iv)
        decrypted = SymmetricCrypto.decrypt_text('AES', 'GCM', cipher, key, iv)
        self.assertEqual(plain, decrypted)

    def test_encrypt_decrypt_chacha20(self):
        key, iv = SymmetricCrypto.generate_key_iv('ChaCha20')
        plain = 'ChaCha20 test'
        cipher = SymmetricCrypto.encrypt_text('ChaCha20', '', plain, key, iv)
        decrypted = SymmetricCrypto.decrypt_text('ChaCha20', '', cipher, key, iv)
        self.assertEqual(plain, decrypted)

    def test_encrypt_decrypt_des(self):
        key, iv = SymmetricCrypto.generate_key_iv('DES')
        plain = 'DES test'
        cipher = SymmetricCrypto.encrypt_text('DES', 'CBC', plain, key, iv)
        decrypted = SymmetricCrypto.decrypt_text('DES', 'CBC', cipher, key, iv)
        self.assertEqual(plain, decrypted)

    def test_encrypt_decrypt_3des(self):
        key, iv = SymmetricCrypto.generate_key_iv('3DES')
        plain = '3DES test'
        cipher = SymmetricCrypto.encrypt_text('3DES', 'CBC', plain, key, iv)
        decrypted = SymmetricCrypto.decrypt_text('3DES', 'CBC', cipher, key, iv)
        self.assertEqual(plain, decrypted)


class TestAsymmetricCrypto(unittest.TestCase):
    """Test RSA and ECC operations."""
    def test_rsa_keygen_encrypt_decrypt(self):
        priv, pub = AsymmetricCrypto.generate_rsa_keypair(1024)  # smaller for speed
        plain = 'RSA test'
        cipher = AsymmetricCrypto.encrypt_rsa(pub, plain)
        decrypted = AsymmetricCrypto.decrypt_rsa(priv, cipher)
        self.assertEqual(plain, decrypted)

    def test_rsa_sign_verify(self):
        priv, pub = AsymmetricCrypto.generate_rsa_keypair(1024)
        msg = 'message to sign'
        sig = AsymmetricCrypto.sign_rsa(priv, msg)
        self.assertTrue(AsymmetricCrypto.verify_rsa(pub, msg, sig))
        self.assertFalse(AsymmetricCrypto.verify_rsa(pub, msg + 'x', sig))

    def test_ecc_keygen(self):
        priv, pub = AsymmetricCrypto.generate_ecc_keypair()
        self.assertIsInstance(priv, type(AsymmetricCrypto.generate_ecc_keypair()[0]))
        self.assertIsInstance(pub, type(AsymmetricCrypto.generate_ecc_keypair()[1]))

    def test_ecc_sign_verify(self):
        priv, pub = AsymmetricCrypto.generate_ecc_keypair()
        msg = 'ECC message'
        sig = AsymmetricCrypto.sign_ecc(priv, msg)
        self.assertTrue(AsymmetricCrypto.verify_ecc(pub, msg, sig))
        self.assertFalse(AsymmetricCrypto.verify_ecc(pub, msg + 'x', sig))

    def test_ecc_encrypt_decrypt_ecies(self):
        priv, pub = AsymmetricCrypto.generate_ecc_keypair()
        plain = 'ECIES test'
        encrypted = AsymmetricCrypto.encrypt_ecc(pub, plain)
        decrypted = AsymmetricCrypto.decrypt_ecc(priv, encrypted)
        self.assertEqual(plain, decrypted)

    def test_key_to_pem(self):
        priv, pub = AsymmetricCrypto.generate_rsa_keypair(1024)
        pub_pem = AsymmetricCrypto.key_to_pem(public_key=pub)
        self.assertIn('BEGIN PUBLIC KEY', pub_pem)
        priv_pem = AsymmetricCrypto.key_to_pem(private_key=priv)
        self.assertIn('BEGIN PRIVATE KEY', priv_pem)


class TestHashUtils(unittest.TestCase):
    """Test hashing and HMAC."""
    def test_hash_sha256(self):
        data = 'hello'
        h = HashUtils.compute_hash('SHA-256', data)
        self.assertEqual(len(h), 64)

    def test_hmac_sha256(self):
        data = 'message'
        key = 'secret'
        hmac1 = HashUtils.compute_hmac('HMAC-SHA256', data, key)
        self.assertEqual(len(hmac1), 64)


class TestHybridCrypto(unittest.TestCase):
    """Test RSA + AES hybrid encryption."""
    def test_hybrid_encrypt_decrypt(self):
        priv, pub = AsymmetricCrypto.generate_rsa_keypair(1024)
        plain = 'Hybrid test'
        encrypted = HybridCrypto.encrypt('AES', 'RSA', plain, pub)
        decrypted = HybridCrypto.decrypt(encrypted, priv)
        self.assertEqual(plain, decrypted)


class TestFileCrypto(unittest.TestCase):
    """Test file encryption/decryption (both symmetric and hybrid)."""
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, 'test.txt')
        with open(self.test_file, 'w') as f:
            f.write('Hello, file!')

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_symmetric_encrypt_decrypt_password(self):
        enc_data = FileCrypto.encrypt_file_symmetric(self.test_file, password='pass123')
        file_data, filename = FileCrypto.decrypt_file_symmetric(enc_data, password='pass123')
        self.assertEqual(file_data.decode(), 'Hello, file!')
        self.assertEqual(filename, 'test.txt')

    def test_symmetric_encrypt_decrypt_key_iv(self):
        key, iv = SymmetricCrypto.generate_key_iv('AES')
        key_b64 = base64.b64encode(key).decode()
        iv_b64 = base64.b64encode(iv).decode()
        enc_data = FileCrypto.encrypt_file_symmetric(
            self.test_file, algorithm='AES', mode='GCM', key=key_b64, iv=iv_b64
        )
        file_data, filename = FileCrypto.decrypt_file_symmetric(enc_data, key=key_b64)
        self.assertEqual(file_data.decode(), 'Hello, file!')
        self.assertEqual(filename, 'test.txt')

    def test_hybrid_encrypt_decrypt(self):
        priv, pub = AsymmetricCrypto.generate_rsa_keypair(1024)
        pub_pem = AsymmetricCrypto.key_to_pem(public_key=pub)
        priv_pem = AsymmetricCrypto.key_to_pem(private_key=priv)
        enc_data = FileCrypto.encrypt_file_hybrid(self.test_file, pub_pem)
        file_data, filename = FileCrypto.decrypt_file_hybrid(enc_data, priv_pem)
        self.assertEqual(file_data.decode(), 'Hello, file!')
        self.assertEqual(filename, 'test.txt')

    def test_text_encrypt_decrypt(self):
        text = 'Some secret text'
        enc = FileCrypto.encrypt_text_file(text, password='pass')
        dec = FileCrypto.decrypt_text_file(enc, password='pass')
        self.assertEqual(dec, text)


class TestFileSharingManager(unittest.TestCase):
    """Test sharing mechanism, including one-time download."""
    def setUp(self):
        self.temp_shares = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        # Initialize with an empty JSON object
        with open(self.temp_shares.name, 'w') as f:
            json.dump({}, f)
        self.temp_shares.close()
        self.fsm = FileSharingManager(self.temp_shares.name)
        self.sender = 'alice@ex.com'
        self.recipient = 'bob@ex.com'
        self.test_data = b'some encrypted file content'

    def tearDown(self):
        os.unlink(self.temp_shares.name)

    def test_share_and_retrieve(self):
        share_id = self.fsm.share_file(self.sender, self.recipient, self.test_data)
        files = self.fsm.get_shared_files(self.recipient)
        self.assertIn(share_id, files)
        retrieved = self.fsm.get_shared_file(self.recipient, share_id)
        self.assertEqual(retrieved['encrypted_data'], self.test_data)
        self.assertEqual(retrieved['sender'], self.sender)
        self.assertFalse(retrieved['corrupted'])

    def test_one_time_download(self):
        share_id = self.fsm.share_file(self.sender, self.recipient, self.test_data, one_time=True)
        # first access -> ok
        file1 = self.fsm.get_shared_file(self.recipient, share_id)
        self.assertIsNotNone(file1)
        # second access -> should be corrupted/None
        file2 = self.fsm.get_shared_file(self.recipient, share_id)
        self.assertIsNone(file2)
        # check that it's marked corrupted
        files = self.fsm.get_shared_files(self.recipient)
        self.assertTrue(files[share_id]['corrupted'])

    def test_metadata(self):
        meta = {'custom': 'value', 'algorithm': 'AES'}
        share_id = self.fsm.share_file(self.sender, self.recipient, self.test_data, metadata=meta)
        retrieved = self.fsm.get_shared_file(self.recipient, share_id)
        self.assertEqual(retrieved['metadata']['custom'], 'value')

    def test_remove_shared_file(self):
        share_id = self.fsm.share_file(self.sender, self.recipient, self.test_data)
        self.fsm.remove_shared_file(self.recipient, share_id)
        files = self.fsm.get_shared_files(self.recipient)
        self.assertNotIn(share_id, files)

    def test_mark_viewed_downloaded(self):
        share_id = self.fsm.share_file(self.sender, self.recipient, self.test_data)
        self.fsm.mark_as_viewed(self.recipient, share_id)
        files = self.fsm.get_shared_files(self.recipient)
        self.assertTrue(files[share_id]['viewed'])
        self.fsm.mark_as_downloaded(self.recipient, share_id)
        files = self.fsm.get_shared_files(self.recipient)
        self.assertTrue(files[share_id]['downloaded'])

    def test_share_stats(self):
        self.fsm.share_file(self.sender, self.recipient, self.test_data, one_time=True)
        self.fsm.share_file(self.sender, self.recipient, b'data2', one_time=False)
        stats = self.fsm.get_share_stats()
        self.assertEqual(stats['total_shares'], 2)
        self.assertEqual(stats['one_time_shares'], 1)
        self.assertEqual(stats['active_shares'], 2)  # none downloaded yet


if __name__ == '__main__':
    unittest.main()