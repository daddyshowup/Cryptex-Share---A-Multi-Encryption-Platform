# gmail = admin@encryption.suite
# pass = Admin@123#
# -------------------------------------- #

# BY Rohit Shrestha --- <> 
# Tool Based on Encryption Algorithm and Sharing ## ....... {}

# # # # # # # # # # # # # # # # # # # # # # # # # # # # 

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import seaborn as sns
import numpy as np
import argparse
import json
import os
import sys
import base64
import secrets
import hashlib
import hmac
import time
from datetime import datetime, timedelta
import threading
import csv
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidSignature
import cryptography.hazmat.primitives.asymmetric.ec as ec
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import zipfile
import io
import pickle
from pathlib import Path
import warnings
import sqlite3
import jsonlines
warnings.filterwarnings('ignore')

# Database setup
class Database:
    def __init__(self, db_file='encryption_suite.db'):
        self.db_file = db_file
        self._init_db()
    
    def _init_db(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at REAL NOT NULL,
            is_admin INTEGER DEFAULT 0,
            last_login REAL,
            login_count INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until REAL
        )
        ''')
        
        # User operations table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_operations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            operation_type TEXT NOT NULL,
            operation_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_email) REFERENCES users (email)
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def execute_query(self, query, params=()):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        conn.close()
    
    def fetch_one(self, query, params=()):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(query, params)
        result = cursor.fetchone()
        conn.close()
        return result
    
    def fetch_all(self, query, params=()):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        return results

class UserManager:
    def __init__(self, data_file='encryption_suite.db'):
        self.db = Database(data_file)
        self.current_user = None
        self.admin_email = "admin@encryption.suite"
        self.admin_password = "Admin@123#"
        self.login_attempts = {}  # Track login attempts per user
        self._create_default_admin()
    
    def _create_default_admin(self):
        # Check if admin exists
        result = self.db.fetch_one("SELECT email FROM users WHERE email = ?", (self.admin_email,))
        
        if not result:
            hashed_password, salt = self._hash_password(self.admin_password)
            
            self.db.execute_query('''
            INSERT INTO users (email, username, password_hash, salt, created_at, is_admin, active)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                self.admin_email,
                'admin',
                hashed_password.decode(),
                base64.urlsafe_b64encode(salt).decode(),
                time.time(),
                1,
                1
            ))
    
    def _hash_password(self, password, salt=None):
        if salt is None:
            salt = secrets.token_bytes(32)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    def is_user_locked_out(self, email):
        """Check if user is locked out due to too many failed attempts"""
        if email in self.login_attempts:
            attempts_data = self.login_attempts[email]
            if attempts_data['attempts'] >= 3:
                lockout_time = attempts_data.get('lockout_until')
                if lockout_time and time.time() < lockout_time:
                    remaining = int((lockout_time - time.time()) / 60)
                    return True, f"Account locked. Try again in {remaining} minutes"
                elif lockout_time and time.time() >= lockout_time:
                    # Reset after lockout period
                    self.login_attempts.pop(email, None)
                    return False, None
        return False, None
    
    def register(self, email, username, password, confirm_password, is_admin=False):
        if password != confirm_password:
            return False, "Passwords do not match"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if '@' not in email or '.' not in email:
            return False, "Invalid email format"
        
        # Check if user already exists
        existing_email = self.db.fetch_one("SELECT email FROM users WHERE email = ?", (email,))
        existing_username = self.db.fetch_one("SELECT email FROM users WHERE username = ?", (username,))
        
        if existing_email or existing_username:
            return False, "User already exists"
        
        hashed_password, salt = self._hash_password(password)
        
        self.db.execute_query('''
        INSERT INTO users (email, username, password_hash, salt, created_at, is_admin, active)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            email,
            username,
            hashed_password.decode(),
            base64.urlsafe_b64encode(salt).decode(),
            time.time(),
            1 if is_admin else 0,
            1
        ))
        
        return True, "Registration successful"
    
    def login(self, identifier, password):
        # Check if user exists and get email
        result = self.db.fetch_one(
            "SELECT email, username, password_hash, salt, is_admin, active FROM users WHERE email = ? OR username = ?",
            (identifier, identifier)
        )
        
        if not result:
            return False, "User not found"
        
        email, username, stored_hash, stored_salt, is_admin, active = result
        
        # Check if account is locked
        locked, message = self.is_user_locked_out(email)
        if locked:
            return False, message
        
        if not active:
            return False, "Account is deactivated"
        
        salt = base64.urlsafe_b64decode(stored_salt.encode())
        hashed_password, _ = self._hash_password(password, salt)
        
        if hashed_password.decode() == stored_hash:
            # Successful login - reset attempts
            if email in self.login_attempts:
                self.login_attempts.pop(email)
            
            # Update user record
            self.db.execute_query(
                "UPDATE users SET last_login = ?, login_count = login_count + 1, failed_attempts = 0, lockout_until = NULL WHERE email = ?",
                (time.time(), email)
            )
            
            self.current_user = {
                'email': email,
                'username': username,
                'is_admin': bool(is_admin)
            }
            
            return True, f"Welcome {username}!"
        else:
            # Failed login - track attempts
            if email not in self.login_attempts:
                self.login_attempts[email] = {
                    'attempts': 1,
                    'last_attempt': time.time()
                }
            else:
                self.login_attempts[email]['attempts'] += 1
                self.login_attempts[email]['last_attempt'] = time.time()
            
            attempts_left = 3 - self.login_attempts[email]['attempts']
            
            if self.login_attempts[email]['attempts'] >= 3:
                # Lock account for 2 minutes
                lockout_time = time.time() + 120  # 2 minutes
                self.login_attempts[email]['lockout_until'] = lockout_time
                return False, "Too many failed attempts. Account locked for 2 minutes."
            
            # Update failed attempts in database
            self.db.execute_query(
                "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE email = ?",
                (email,)
            )
            
            return False, f"Invalid password. {attempts_left} attempts remaining"
    
    def logout(self):
        self.current_user = None
        return True
    
    def get_all_users(self):
        results = self.db.fetch_all(
            "SELECT email, username, password_hash, salt, created_at, is_admin, last_login, login_count, active, failed_attempts, lockout_until FROM users"
        )
        
        users = {}
        for row in results:
            email, username, password_hash, salt, created_at, is_admin, last_login, login_count, active, failed_attempts, lockout_until = row
            
            # Get user operations
            ops_results = self.db.fetch_all(
                "SELECT operation_type, operation_count FROM user_operations WHERE user_email = ?",
                (email,)
            )
            
            encryption_operations = {
                'symmetric': 0,
                'asymmetric': 0,
                'hashing': 0,
                'signatures': 0,
                'file_encryption': 0,
                'file_sharing': 0
            }
            
            for op_type, count in ops_results:
                if op_type in encryption_operations:
                    encryption_operations[op_type] = count
            
            users[email] = {
                'username': username,
                'password': password_hash,
                'salt': salt,
                'created_at': created_at,
                'is_admin': bool(is_admin),
                'last_login': last_login,
                'login_count': login_count,
                'active': bool(active),
                'encryption_operations': encryption_operations,
                'failed_attempts': failed_attempts,
                'lockout_until': lockout_until
            }
        
        return users
    
    def get_user_by_email(self, email):
        result = self.db.fetch_one(
            "SELECT email, username, password_hash, salt, created_at, is_admin, last_login, login_count, active, failed_attempts, lockout_until FROM users WHERE email = ?",
            (email,)
        )
        
        if not result:
            return None
        
        email, username, password_hash, salt, created_at, is_admin, last_login, login_count, active, failed_attempts, lockout_until = result
        
        # Get user operations
        ops_results = self.db.fetch_all(
            "SELECT operation_type, operation_count FROM user_operations WHERE user_email = ?",
            (email,)
        )
        
        encryption_operations = {
            'symmetric': 0,
            'asymmetric': 0,
            'hashing': 0,
            'signatures': 0,
            'file_encryption': 0,
            'file_sharing': 0
        }
        
        for op_type, count in ops_results:
            if op_type in encryption_operations:
                encryption_operations[op_type] = count
        
        return {
            'username': username,
            'password': password_hash,
            'salt': salt,
            'created_at': created_at,
            'is_admin': bool(is_admin),
            'last_login': last_login,
            'login_count': login_count,
            'active': bool(active),
            'encryption_operations': encryption_operations,
            'failed_attempts': failed_attempts,
            'lockout_until': lockout_until
        }
    
    def delete_user(self, email):
        if email == self.admin_email:
            return False, "Cannot delete admin account"
        
        if self.current_user and email == self.current_user['email']:
            return False, "Cannot delete your own account while logged in"
        
        self.db.execute_query("DELETE FROM users WHERE email = ?", (email,))
        self.db.execute_query("DELETE FROM user_operations WHERE user_email = ?", (email,))
        
        return True, "User deleted successfully"
    
    def toggle_user_status(self, email, active):
        if email == self.admin_email:
            return False, "Cannot modify admin account"
        
        self.db.execute_query(
            "UPDATE users SET active = ? WHERE email = ?",
            (1 if active else 0, email)
        )
        
        status = "activated" if active else "deactivated"
        return True, f"User {status} successfully"
    
    def promote_to_admin(self, email):
        user = self.get_user_by_email(email)
        if not user:
            return False, "User not found"
        
        if user.get('is_admin', False):
            return False, "User is already an admin"
        
        self.db.execute_query(
            "UPDATE users SET is_admin = 1 WHERE email = ?",
            (email,)
        )
        
        return True, "User promoted to admin successfully"
    
    def demote_from_admin(self, email):
        if email == self.admin_email:
            return False, "Cannot demote main admin"
        
        user = self.get_user_by_email(email)
        if not user:
            return False, "User not found"
        
        if not user.get('is_admin', False):
            return False, "User is not an admin"
        
        self.db.execute_query(
            "UPDATE users SET is_admin = 0 WHERE email = ?",
            (email,)
        )
        
        return True, "User demoted from admin successfully"
    
    def get_system_stats(self):
        users = self.get_all_users()
        stats = {
            'total_users': len(users),
            'active_users': sum(1 for u in users.values() if u.get('active', True)),
            'admin_users': sum(1 for u in users.values() if u.get('is_admin', False)),
            'total_logins': sum(u.get('login_count', 0) for u in users.values()),
            'recent_users': sum(1 for u in users.values() if u.get('last_login', 0) > time.time() - 86400),
            'locked_users': sum(1 for email in self.login_attempts 
                               if self.login_attempts[email].get('attempts', 0) >= 3 and
                               self.login_attempts[email].get('lockout_until', 0) > time.time())
        }
        return stats
    
    def update_user_operation(self, email, operation_type):
        # Check if operation exists
        result = self.db.fetch_one(
            "SELECT operation_count FROM user_operations WHERE user_email = ? AND operation_type = ?",
            (email, operation_type)
        )
        
        if result:
            # Update existing
            self.db.execute_query(
                "UPDATE user_operations SET operation_count = operation_count + 1 WHERE user_email = ? AND operation_type = ?",
                (email, operation_type)
            )
        else:
            # Insert new
            self.db.execute_query(
                "INSERT INTO user_operations (user_email, operation_type, operation_count) VALUES (?, ?, ?)",
                (email, operation_type, 1)
            )

class SecurityMonitor:
    def __init__(self, monitor_file='security_logs.jsonl'):
        self.monitor_file = monitor_file
        self._ensure_monitor_file()
    
    def _ensure_monitor_file(self):
        if not os.path.exists(self.monitor_file):
            # Initialize with default empty file
            with open(self.monitor_file, 'w') as f:
                pass
    
    def log_event(self, event_type, details=None):
        try:
            log_entry = {
                'timestamp': time.time(),
                'type': event_type,
                'details': details or {}
            }
            
            # Append as JSONL (one JSON per line)
            with open(self.monitor_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        except Exception as e:
            print(f"Error logging security event: {e}")
    
    def get_security_stats(self):
        try:
            failed_decrypts = 0
            successful_decrypts = 0
            failed_logins = 0
            successful_logins = 0
            brute_force_attempts = 0
            attack_types = {
                'brute_force': 0,
                'invalid_format': 0,
                'unauthorized_access': 0,
                'malformed_data': 0
            }
            daily_stats = {}
            
            # Read JSONL file
            with open(self.monitor_file, 'r') as f:
                for line in f:
                    if line.strip():
                        log_entry = json.loads(line.strip())
                        
                        event_type = log_entry.get('type')
                        timestamp = log_entry.get('timestamp', time.time())
                        
                        # Get date from timestamp
                        log_date = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d')
                        
                        if log_date not in daily_stats:
                            daily_stats[log_date] = {
                                'failed_decrypts': 0,
                                'successful_decrypts': 0,
                                'failed_logins': 0,
                                'successful_logins': 0,
                                'brute_force_attempts': 0
                            }
                        
                        if event_type == 'failed_decrypt':
                            failed_decrypts += 1
                            daily_stats[log_date]['failed_decrypts'] += 1
                        elif event_type == 'successful_decrypt':
                            successful_decrypts += 1
                            daily_stats[log_date]['successful_decrypts'] += 1
                        elif event_type == 'failed_login':
                            failed_logins += 1
                            daily_stats[log_date]['failed_logins'] += 1
                        elif event_type == 'successful_login':
                            successful_logins += 1
                            daily_stats[log_date]['successful_logins'] += 1
                        elif event_type == 'brute_force':
                            brute_force_attempts += 1
                            daily_stats[log_date]['brute_force_attempts'] += 1
                            attack_types['brute_force'] += 1
                        elif event_type == 'invalid_format':
                            attack_types['invalid_format'] += 1
                        elif event_type == 'unauthorized_access':
                            attack_types['unauthorized_access'] += 1
                        elif event_type == 'malformed_data':
                            attack_types['malformed_data'] += 1
            
            # Calculate today's stats
            today = datetime.now().strftime('%Y-%m-%d')
            today_stats = daily_stats.get(today, {
                'failed_decrypts': 0,
                'successful_decrypts': 0,
                'failed_logins': 0,
                'successful_logins': 0,
                'brute_force_attempts': 0
            })
            
            # Calculate weekly stats
            week_ago = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
            weekly_stats = {
                'failed_decrypts': 0,
                'successful_decrypts': 0,
                'failed_logins': 0,
                'successful_logins': 0,
                'brute_force_attempts': 0
            }
            
            for date, stats in daily_stats.items():
                if date >= week_ago:
                    for key in weekly_stats:
                        weekly_stats[key] += stats.get(key, 0)
            
            # Get last 10 suspicious activities
            suspicious_activities = []
            try:
                with open(self.monitor_file, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-10:]:  # Get last 10 lines
                        if line.strip():
                            suspicious_activities.append(json.loads(line.strip()))
            except:
                pass
            
            return {
                'failed_decrypts': failed_decrypts,
                'successful_decrypts': successful_decrypts,
                'failed_logins': failed_logins,
                'successful_logins': successful_logins,
                'brute_force_attempts': brute_force_attempts,
                'attack_types': attack_types,
                'today_stats': today_stats,
                'weekly_stats': weekly_stats,
                'suspicious_activities': suspicious_activities[-10:]  # Last 10 activities
            }
        except Exception as e:
            print(f"Error reading security stats: {e}")
            return {
                'failed_decrypts': 0,
                'successful_decrypts': 0,
                'failed_logins': 0,
                'successful_logins': 0,
                'brute_force_attempts': 0,
                'attack_types': {},
                'today_stats': {},
                'weekly_stats': {},
                'suspicious_activities': []
            }

class FileCrypto:
    @staticmethod
    def encrypt_file_symmetric(file_path, algorithm='AES', mode='CBC', password=None, key=None, iv=None):
        """Encrypt a file with symmetric encryption"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            filename = os.path.basename(file_path)
            file_size = len(file_data)
            
            if password:
                # Derive key from password using scrypt
                salt = secrets.token_bytes(16)
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
                if not iv:
                    iv = secrets.token_bytes(16)
                
                # Encrypt the data
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                    elif mode == 'GCM':
                        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                
                encryptor = cipher.encryptor()
                
                if algorithm in ['AES'] and mode in ['CBC']:
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(file_data) + padder.finalize()
                    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                else:
                    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
                
                # Package everything together
                package = {
                    'salt': salt,
                    'iv': iv,
                    'encrypted_data': encrypted_data,
                    'algorithm': algorithm,
                    'mode': mode,
                    'original_filename': filename,
                    'file_size': file_size,
                    'encryption_method': 'password',
                    'timestamp': time.time()
                }
                
                if algorithm == 'AES' and mode == 'GCM':
                    package['tag'] = encryptor.tag
                
                return pickle.dumps(package)
            
            elif key:
                if not iv:
                    iv = secrets.token_bytes(16)
                
                key_bin = base64.b64decode(key) if isinstance(key, str) else key
                iv_bin = base64.b64decode(iv) if isinstance(iv, str) else iv
                
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key_bin), modes.CBC(iv_bin), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key_bin), modes.CTR(iv_bin), backend=default_backend())
                    elif mode == 'GCM':
                        cipher = Cipher(algorithms.AES(key_bin), modes.GCM(iv_bin), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key_bin, iv_bin), mode=None, backend=default_backend())
                
                encryptor = cipher.encryptor()
                
                if algorithm in ['AES'] and mode in ['CBC']:
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(file_data) + padder.finalize()
                    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                else:
                    encrypted_data = encryptor.update(file_data) + encryptor.finalize()
                
                package = {
                    'iv': iv_bin,
                    'encrypted_data': encrypted_data,
                    'algorithm': algorithm,
                    'mode': mode,
                    'original_filename': filename,
                    'file_size': file_size,
                    'encryption_method': 'key',
                    'timestamp': time.time()
                }
                
                if algorithm == 'AES' and mode == 'GCM':
                    package['tag'] = encryptor.tag
                
                return pickle.dumps(package)
                
        except Exception as e:
            raise Exception(f"File encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_file_symmetric(encrypted_data, password=None, key=None):
        """Decrypt an encrypted file package"""
        try:
            package = pickle.loads(encrypted_data)
            
            if package.get('encryption_method') == 'password':
                salt = package['salt']
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
                iv = package['iv']
                algorithm = package['algorithm']
                mode = package.get('mode', 'CBC')
                
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                    elif mode == 'GCM':
                        tag = package['tag']
                        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(package['encrypted_data']) + decryptor.finalize()
                
                if algorithm in ['AES'] and mode in ['CBC']:
                    unpadder = padding.PKCS7(128).unpadder()
                    file_data = unpadder.update(decrypted_data) + unpadder.finalize()
                else:
                    file_data = decrypted_data
                
                return file_data, package['original_filename']
            
            elif package.get('encryption_method') == 'key':
                key_bin = base64.b64decode(key) if isinstance(key, str) else key
                iv = package['iv']
                algorithm = package['algorithm']
                mode = package.get('mode', 'CBC')
                
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key_bin), modes.CBC(iv), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key_bin), modes.CTR(iv), backend=default_backend())
                    elif mode == 'GCM':
                        tag = package['tag']
                        cipher = Cipher(algorithms.AES(key_bin), modes.GCM(iv, tag), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key_bin, iv), mode=None, backend=default_backend())
                
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(package['encrypted_data']) + decryptor.finalize()
                
                if algorithm in ['AES'] and mode in ['CBC']:
                    unpadder = padding.PKCS7(128).unpadder()
                    file_data = unpadder.update(decrypted_data) + unpadder.finalize()
                else:
                    file_data = decrypted_data
                
                return file_data, package['original_filename']
                
        except Exception as e:
            raise Exception(f"File decryption failed: {str(e)}")
    
    @staticmethod
    def encrypt_file_hybrid(file_path, public_key_pem):
        """Encrypt file using hybrid encryption (RSA + AES)"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            filename = os.path.basename(file_path)
            file_size = len(file_data)
            
            # Generate random symmetric key
            sym_key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)
            
            # Encrypt file with symmetric key using AES-GCM
            cipher = Cipher(algorithms.AES(sym_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(file_data) + encryptor.finalize()
            tag = encryptor.tag
            
            # Encrypt symmetric key with RSA
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
            encrypted_key = public_key.encrypt(
                sym_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            package = {
                'encrypted_key': encrypted_key,
                'iv': iv,
                'tag': tag,
                'encrypted_data': encrypted_data,
                'original_filename': filename,
                'file_size': file_size,
                'algorithm': 'AES-GCM-RSA-Hybrid',
                'encryption_method': 'hybrid',
                'timestamp': time.time()
            }
            
            return pickle.dumps(package)
            
        except Exception as e:
            raise Exception(f"Hybrid file encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_file_hybrid(encrypted_data, private_key_pem):
        """Decrypt hybrid encrypted file"""
        try:
            package = pickle.loads(encrypted_data)
            
            # Decrypt symmetric key with private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
            
            sym_key = private_key.decrypt(
                package['encrypted_key'],
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt file data with symmetric key
            cipher = Cipher(algorithms.AES(sym_key), modes.GCM(package['iv'], package['tag']), 
                          backend=default_backend())
            decryptor = cipher.decryptor()
            file_data = decryptor.update(package['encrypted_data']) + decryptor.finalize()
            
            return file_data, package['original_filename']
            
        except Exception as e:
            raise Exception(f"Hybrid file decryption failed: {str(e)}")
    
    @staticmethod
    def encrypt_text_file(text, algorithm='AES', mode='CBC', password=None, key=None, iv=None):
        """Encrypt text as a file"""
        try:
            if password:
                salt = secrets.token_bytes(16)
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
                if not iv:
                    iv = secrets.token_bytes(16)
                
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                    elif mode == 'GCM':
                        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                
                encryptor = cipher.encryptor()
                
                if algorithm in ['AES'] and mode in ['CBC']:
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(text.encode()) + padder.finalize()
                    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                else:
                    encrypted_data = encryptor.update(text.encode()) + encryptor.finalize()
                
                package = {
                    'salt': salt,
                    'iv': iv,
                    'encrypted_data': encrypted_data,
                    'algorithm': algorithm,
                    'mode': mode,
                    'encryption_method': 'password',
                    'timestamp': time.time()
                }
                
                if algorithm == 'AES' and mode == 'GCM':
                    package['tag'] = encryptor.tag
                
                return pickle.dumps(package)
            
            elif key:
                if not iv:
                    iv = secrets.token_bytes(16)
                
                key_bin = base64.b64decode(key) if isinstance(key, str) else key
                iv_bin = base64.b64decode(iv) if isinstance(iv, str) else iv
                
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key_bin), modes.CBC(iv_bin), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key_bin), modes.CTR(iv_bin), backend=default_backend())
                    elif mode == 'GCM':
                        cipher = Cipher(algorithms.AES(key_bin), modes.GCM(iv_bin), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key_bin, iv_bin), mode=None, backend=default_backend())
                
                encryptor = cipher.encryptor()
                
                if algorithm in ['AES'] and mode in ['CBC']:
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(text.encode()) + padder.finalize()
                    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                else:
                    encrypted_data = encryptor.update(text.encode()) + encryptor.finalize()
                
                package = {
                    'iv': iv_bin,
                    'encrypted_data': encrypted_data,
                    'algorithm': algorithm,
                    'mode': mode,
                    'encryption_method': 'key',
                    'timestamp': time.time()
                }
                
                if algorithm == 'AES' and mode == 'GCM':
                    package['tag'] = encryptor.tag
                
                return pickle.dumps(package)
                
        except Exception as e:
            raise Exception(f"Text encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_text_file(encrypted_data, password=None, key=None):
        """Decrypt encrypted text file"""
        try:
            package = pickle.loads(encrypted_data)
            
            if package.get('encryption_method') == 'password':
                salt = package['salt']
                kdf = Scrypt(
                    salt=salt,
                    length=32,
                    n=2**14,
                    r=8,
                    p=1,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode())
                iv = package['iv']
                algorithm = package['algorithm']
                mode = package.get('mode', 'CBC')
                
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                    elif mode == 'GCM':
                        tag = package['tag']
                        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(package['encrypted_data']) + decryptor.finalize()
                
                if algorithm in ['AES'] and mode in ['CBC']:
                    unpadder = padding.PKCS7(128).unpadder()
                    text_data = unpadder.update(decrypted_data) + unpadder.finalize()
                else:
                    text_data = decrypted_data
                
                return text_data.decode()
            
            elif package.get('encryption_method') == 'key':
                key_bin = base64.b64decode(key) if isinstance(key, str) else key
                iv = package['iv']
                algorithm = package['algorithm']
                mode = package.get('mode', 'CBC')
                
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key_bin), modes.CBC(iv), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key_bin), modes.CTR(iv), backend=default_backend())
                    elif mode == 'GCM':
                        tag = package['tag']
                        cipher = Cipher(algorithms.AES(key_bin), modes.GCM(iv, tag), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key_bin, iv), mode=None, backend=default_backend())
                
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(package['encrypted_data']) + decryptor.finalize()
                
                if algorithm in ['AES'] and mode in ['CBC']:
                    unpadder = padding.PKCS7(128).unpadder()
                    text_data = unpadder.update(decrypted_data) + unpadder.finalize()
                else:
                    text_data = decrypted_data
                
                return text_data.decode()
                
        except Exception as e:
            raise Exception(f"Text decryption failed: {str(e)}")

class SymmetricCrypto:
    @staticmethod
    def generate_key_iv(algorithm='AES'):
        if algorithm == 'AES':
            key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)
        elif algorithm == 'DES':
            key = secrets.token_bytes(8)
            iv = secrets.token_bytes(8)
        elif algorithm == '3DES':
            key = secrets.token_bytes(24)
            iv = secrets.token_bytes(8)
        elif algorithm == 'ChaCha20':
            key = secrets.token_bytes(32)
            iv = secrets.token_bytes(16)
        else:
            raise ValueError("Unsupported algorithm")
        return key, iv
    
    @staticmethod
    def encrypt_text(algorithm, mode, text, key, iv=None):
        try:
            if algorithm == 'AES':
                if mode == 'CBC':
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                elif mode == 'CTR':
                    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                elif mode == 'GCM':
                    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
                else:
                    raise ValueError("Unsupported mode")
            elif algorithm == 'DES':
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            elif algorithm == '3DES':
                cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
            elif algorithm == 'ChaCha20':
                cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
            else:
                raise ValueError("Unsupported algorithm")
            
            encryptor = cipher.encryptor()
            
            if algorithm in ['AES', 'DES', '3DES'] and mode in ['CBC']:
                padder = padding.PKCS7(128 if algorithm == 'AES' else 64).padder()
                padded_data = padder.update(text.encode()) + padder.finalize()
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            else:
                ciphertext = encryptor.update(text.encode()) + encryptor.finalize()
            
            if algorithm == 'AES' and mode == 'GCM':
                return base64.b64encode(iv + encryptor.tag + ciphertext).decode()
            else:
                return base64.b64encode(iv + ciphertext).decode()
                
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_text(algorithm, mode, ciphertext, key, iv=None):
        try:
            data = base64.b64decode(ciphertext)
            
            if algorithm == 'AES' and mode == 'GCM':
                iv = data[:16]
                tag = data[16:32]
                encrypted_data = data[32:]
                cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            else:
                iv = data[:len(iv)] if iv else data[:16]
                encrypted_data = data[len(iv):]
                
                if algorithm == 'AES':
                    if mode == 'CBC':
                        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    elif mode == 'CTR':
                        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
                    else:
                        raise ValueError("Unsupported mode")
                elif algorithm == 'DES':
                    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                elif algorithm == '3DES':
                    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
                elif algorithm == 'ChaCha20':
                    cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
                else:
                    raise ValueError("Unsupported algorithm")
            
            decryptor = cipher.decryptor()
            
            if algorithm in ['AES', 'DES', '3DES'] and mode in ['CBC']:
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                unpadder = padding.PKCS7(128 if algorithm == 'AES' else 64).unpadder()
                plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
            else:
                plaintext = decryptor.update(encrypted_data) + decryptor.finalize()
            
            return plaintext.decode()
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

class AsymmetricCrypto:
    @staticmethod
    def generate_rsa_keypair(bits=2048):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def generate_ecc_keypair():
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def encrypt_rsa(public_key, plaintext):
        ciphertext = public_key.encrypt(
            plaintext.encode(),
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()
    
    @staticmethod
    def decrypt_rsa(private_key, ciphertext):
        data = base64.b64decode(ciphertext)
        plaintext = private_key.decrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    
    @staticmethod
    def sign_rsa(private_key, message):
        signature = private_key.sign(
            message.encode(),
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def verify_rsa(public_key, message, signature):
        try:
            public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    @staticmethod
    def encrypt_ecc(public_key, plaintext):
        """Encrypt using ECC with ECIES (Elliptic Curve Integrated Encryption Scheme)"""
        try:
            # Generate ephemeral key pair
            ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            ephemeral_public_key = ephemeral_private_key.public_key()
            
            # Compute shared secret
            shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
            
            # Derive symmetric key from shared secret
            kdf = hashes.Hash(hashes.SHA256(), backend=default_backend())
            kdf.update(shared_secret)
            symmetric_key = kdf.finalize()[:32]  # Use first 32 bytes for AES-256
            
            # Generate IV
            iv = secrets.token_bytes(16)
            
            # Encrypt data with symmetric key
            cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            tag = encryptor.tag
            
            # Serialize ephemeral public key
            ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Package everything
            encrypted_package = {
                'ephemeral_public_key': base64.b64encode(ephemeral_pub_bytes).decode(),
                'iv': base64.b64encode(iv).decode(),
                'tag': base64.b64encode(tag).decode(),
                'ciphertext': base64.b64encode(ciphertext).decode()
            }
            
            return json.dumps(encrypted_package)
            
        except Exception as e:
            raise Exception(f"ECC encryption failed: {str(e)}")
    
    @staticmethod
    def decrypt_ecc(private_key, encrypted_data):
        """Decrypt ECC encrypted data"""
        try:
            package = json.loads(encrypted_data)
            
            # Deserialize ephemeral public key
            ephemeral_pub_bytes = base64.b64decode(package['ephemeral_public_key'])
            ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(),
                ephemeral_pub_bytes
            )
            
            # Compute shared secret
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
            
            # Derive symmetric key from shared secret
            kdf = hashes.Hash(hashes.SHA256(), backend=default_backend())
            kdf.update(shared_secret)
            symmetric_key = kdf.finalize()[:32]
            
            # Get IV and tag
            iv = base64.b64decode(package['iv'])
            tag = base64.b64decode(package['tag'])
            ciphertext = base64.b64decode(package['ciphertext'])
            
            # Decrypt data with symmetric key
            cipher = Cipher(algorithms.AES(symmetric_key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext.decode()
            
        except Exception as e:
            raise Exception(f"ECC decryption failed: {str(e)}")
    
    @staticmethod
    def sign_ecc(private_key, message):
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return base64.b64encode(signature).decode()
    
    @staticmethod
    def verify_ecc(public_key, message, signature):
        try:
            public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
    
    @staticmethod
    def key_to_pem(private_key=None, public_key=None):
        if private_key:
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        elif public_key:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        return None
    
    @staticmethod
    def ecc_key_to_pem(private_key=None, public_key=None):
        if private_key:
            return private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        elif public_key:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        return None

class HashUtils:
    @staticmethod
    def compute_hash(algorithm, data):
        if isinstance(data, str):
            data = data.encode()
        
        if algorithm == 'SHA-256':
            hash_obj = hashlib.sha256(data)
        elif algorithm == 'SHA-512':
            hash_obj = hashlib.sha512(data)
        elif algorithm == 'SHA3-256':
            hash_obj = hashlib.sha3_256(data)
        else:
            raise ValueError("Unsupported hash algorithm")
        
        return hash_obj.hexdigest()
    
    @staticmethod
    def compute_hmac(algorithm, data, key):
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        
        if algorithm == 'HMAC-SHA256':
            hmac_obj = hmac.new(key, data, hashlib.sha256)
        elif algorithm == 'HMAC-SHA512':
            hmac_obj = hmac.new(key, data, hashlib.sha512)
        else:
            raise ValueError("Unsupported HMAC algorithm")
        
        return hmac_obj.hexdigest()

class HybridCrypto:
    @staticmethod
    def encrypt(symmetric_algo, asymmetric_algo, plaintext, public_key):
        # Generate symmetric key and IV
        key, iv = SymmetricCrypto.generate_key_iv(symmetric_algo)
        
        # Encrypt data with symmetric key
        ciphertext = SymmetricCrypto.encrypt_text(symmetric_algo, 'CBC', plaintext, key, iv)
        
        # Encrypt symmetric key with public key
        encrypted_key = AsymmetricCrypto.encrypt_rsa(public_key, base64.b64encode(key).decode())
        
        # Return packaged data
        return {
            'ciphertext': ciphertext,
            'encrypted_key': encrypted_key,
            'iv': base64.b64encode(iv).decode(),
            'algorithm': f"{symmetric_algo}+{asymmetric_algo}"
        }
    
    @staticmethod
    def decrypt(hybrid_data, private_key):
        try:
            # Decrypt symmetric key with private key
            decrypted_key = AsymmetricCrypto.decrypt_rsa(private_key, hybrid_data['encrypted_key'])
            key = base64.b64decode(decrypted_key)
            iv = base64.b64decode(hybrid_data['iv'])
            
            # Decrypt data with symmetric key
            algorithms = hybrid_data['algorithm'].split('+')
            symmetric_algo = algorithms[0] if len(algorithms) > 0 else 'AES'
            
            plaintext = SymmetricCrypto.decrypt_text(symmetric_algo, 'CBC', hybrid_data['ciphertext'], key, iv)
            return plaintext
        except Exception as e:
            raise Exception(f"Hybrid decryption failed: {str(e)}")

class FileSharingManager:
    def __init__(self, data_file='shared_files.json'):
        self.data_file = data_file
        self._ensure_data_file()
    
    def _ensure_data_file(self):
        if not os.path.exists(self.data_file):
            with open(self.data_file, 'w') as f:
                json.dump({}, f)
    
    def share_file(self, sender_email, recipient_email, encrypted_data, metadata=None, one_time=False):
        """Store shared file information with optional one-time download"""
        try:
            with open(self.data_file, 'r') as f:
                shared_files = json.load(f)
            
            share_id = secrets.token_hex(16)
            timestamp = time.time()
            
            if recipient_email not in shared_files:
                shared_files[recipient_email] = {}
            
            shared_files[recipient_email][share_id] = {
                'sender': sender_email,
                'encrypted_data_b64': base64.b64encode(encrypted_data).decode(),
                'timestamp': timestamp,
                'metadata': metadata or {},
                'downloaded': False,
                'viewed': False,
                'one_time': one_time,
                'access_count': 0,
                'corrupted': False,
                'last_access_time': None
            }
            
            with open(self.data_file, 'w') as f:
                json.dump(shared_files, f, indent=2)
            
            return share_id
            
        except Exception as e:
            raise Exception(f"Failed to share file: {str(e)}")
    
    def get_shared_files(self, recipient_email):
        """Get all files shared with a user"""
        try:
            with open(self.data_file, 'r') as f:
                shared_files = json.load(f)
            
            return shared_files.get(recipient_email, {})
        except:
            return {}
    
    def get_shared_file(self, recipient_email, share_id):
        """Get a specific shared file with access control"""
        try:
            with open(self.data_file, 'r') as f:
                shared_files = json.load(f)
        except:
            return None
        
        if recipient_email not in shared_files or share_id not in shared_files[recipient_email]:
            return None
        
        file_data = shared_files[recipient_email][share_id]
        
        # Check if file is corrupted (one-time download already used)
        if file_data.get('corrupted', False):
            return None
        
        # Update access count
        file_data['access_count'] = file_data.get('access_count', 0) + 1
        file_data['last_access_time'] = time.time()
        
        # Check if one-time download should be corrupted
        if file_data.get('one_time', False) and file_data['access_count'] > 1:
            # Mark as corrupted
            file_data['corrupted'] = True
            # Corrupt the data
            corrupted_data = secrets.token_bytes(len(base64.b64decode(file_data['encrypted_data_b64'])))
            file_data['encrypted_data_b64'] = base64.b64encode(corrupted_data).decode()
            file_data['downloaded'] = True
            
            # Save corrupted state
            try:
                with open(self.data_file, 'w') as f:
                    json.dump(shared_files, f, indent=2)
            except:
                pass
            
            return None
        
        # Mark as viewed if first access
        if not file_data['viewed']:
            file_data['viewed'] = True
        
        # Save updated state
        try:
            with open(self.data_file, 'w') as f:
                json.dump(shared_files, f, indent=2)
        except:
            pass
        
        # Return file data
        file_data['encrypted_data'] = base64.b64decode(file_data['encrypted_data_b64'])
        return file_data
    
    def mark_as_viewed(self, recipient_email, share_id):
        """Mark a shared file as viewed"""
        try:
            with open(self.data_file, 'r') as f:
                shared_files = json.load(f)
            
            if recipient_email in shared_files and share_id in shared_files[recipient_email]:
                shared_files[recipient_email][share_id]['viewed'] = True
                
                with open(self.data_file, 'w') as f:
                    json.dump(shared_files, f, indent=2)
                
                return True
            return False
        except:
            return False
    
    def mark_as_downloaded(self, recipient_email, share_id):
        """Mark a shared file as downloaded"""
        try:
            with open(self.data_file, 'r') as f:
                shared_files = json.load(f)
            
            if recipient_email in shared_files and share_id in shared_files[recipient_email]:
                shared_files[recipient_email][share_id]['downloaded'] = True
                
                with open(self.data_file, 'w') as f:
                    json.dump(shared_files, f, indent=2)
                
                return True
            return False
        except:
            return False
    
    def remove_shared_file(self, recipient_email, share_id):
        """Remove a shared file"""
        try:
            with open(self.data_file, 'r') as f:
                shared_files = json.load(f)
            
            if recipient_email in shared_files and share_id in shared_files[recipient_email]:
                del shared_files[recipient_email][share_id]
                
                with open(self.data_file, 'w') as f:
                    json.dump(shared_files, f, indent=2)
                
                return True
            return False
        except:
            return False
    
    def get_share_stats(self):
        """Get statistics about shared files"""
        try:
            with open(self.data_file, 'r') as f:
                shared_files = json.load(f)
            
            total_shares = 0
            one_time_shares = 0
            downloaded_shares = 0
            active_shares = 0
            
            for recipient in shared_files.values():
                for file_data in recipient.values():
                    total_shares += 1
                    if file_data.get('one_time', False):
                        one_time_shares += 1
                    if file_data.get('downloaded', False):
                        downloaded_shares += 1
                    if not file_data.get('corrupted', False):
                        active_shares += 1
            
            return {
                'total_shares': total_shares,
                'one_time_shares': one_time_shares,
                'downloaded_shares': downloaded_shares,
                'active_shares': active_shares
            }
        except:
            return {
                'total_shares': 0,
                'one_time_shares': 0,
                'downloaded_shares': 0,
                'active_shares': 0
            }

class AnalyticsDashboard:
    def __init__(self, parent, user_manager, security_monitor):
        self.parent = parent
        self.user_manager = user_manager
        self.security_monitor = security_monitor
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.setup_ui()
        self.refresh_data()
    
    def setup_ui(self):
        # Title
        title = ttk.Label(self.frame, text="📊 Analytics Dashboard", font=('Arial', 18, 'bold'))
        title.pack(pady=10)
        
        # Create notebook for different analytics sections
        notebook = ttk.Notebook(self.frame)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # User Behavior Analytics Tab
        user_tab = ttk.Frame(notebook)
        notebook.add(user_tab, text="👤 User Analytics")
        self.setup_user_analytics_tab(user_tab)
        
        # Security Monitoring Tab
        security_tab = ttk.Frame(notebook)
        notebook.add(security_tab, text="🔒 Security Monitoring")
        self.setup_security_monitoring_tab(security_tab)
        
        # Refresh button
        refresh_btn = ttk.Button(self.frame, text="🔄 Refresh Analytics", 
                                command=self.refresh_data)
        refresh_btn.pack(pady=10)
    
    def setup_user_analytics_tab(self, parent):
        # Create a scrollable frame for user analytics
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Create a main container with two columns
        main_container = ttk.Frame(scrollable_frame)
        main_container.pack(fill='both', expand=True)
        
        # Left column for first two graphs
        left_column = ttk.Frame(main_container)
        left_column.pack(side='left', fill='both', expand=True)
        
        # Right column for last two graphs (side by side)
        # Right column (container)
        right_column = ttk.Frame(main_container)
        right_column.pack(side='right', fill='both', expand=True)

        # Split right column into charts + instructions
        right_charts = ttk.Frame(right_column)
        right_charts.pack(side='left', fill='both', expand=True)

        right_instructions = ttk.Frame(right_column)
        right_instructions.pack(side='right', fill='y', expand=False)
        right_instructions.config(width=520)
        right_instructions.pack_propagate(False)

        
        # Bar graph: Top users by encrypted files (LEFT COLUMN)
        bar_frame = ttk.LabelFrame(left_column, text="📈 Top Users by Encrypted Files", padding=10)
        bar_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.bar_canvas_frame = ttk.Frame(bar_frame)
        self.bar_canvas_frame.pack(fill='both', expand=True)
        
        # Line graph: New user registrations over time (LEFT COLUMN)
        line_frame = ttk.LabelFrame(left_column, text="📊 New User Registrations Over Time", padding=10)
        line_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.line_canvas_frame = ttk.Frame(line_frame)
        self.line_canvas_frame.pack(fill='both', expand=True)
        
        # Pie chart: Active vs inactive users (RIGHT COLUMN - TOP)
        pie_frame = ttk.LabelFrame( right_charts, text="🥧 Active vs Inactive Users", padding=10)
        pie_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.pie_canvas_frame = ttk.Frame(pie_frame)
        self.pie_canvas_frame.pack(fill='both', expand=True)

        
        # Heatmap: Login time patterns (RIGHT COLUMN - BOTTOM)
        heatmap_frame = ttk.LabelFrame( right_charts, text="🔥 Login Time Patterns (Hour vs Day)", padding=10)
        heatmap_frame.pack(fill='both', expand=True, padx=5, pady=5)

        self.heatmap_canvas_frame = ttk.Frame(heatmap_frame)
        self.heatmap_canvas_frame.pack(fill='both', expand=True)


         # Instructions for User Analytics (RIGHT COLUMN)
        instructions_frame = ttk.LabelFrame( right_instructions, text="📋 User Analytics Instructions", padding=10)
        instructions_frame.pack(fill='both', expand=True, padx=5, pady=5)

        
        instructions_text = """
      ╔══════════════════════════════════════════════════════╗
      ║           📊 USER ANALYTICS DASHBOARD GUIDE          ║
      ╚══════════════════════════════════════════════════════╝

      ┌──────────────────────────────────────────────────────┐
      ║ 📈 TOP USERS BY ENCRYPTED FILES                      ║
      ├──────────────────────────────────────────────────────┤
      │ • Shows top 5 users based on total encryption        │
      │   operations performed                               │
      │ • Operations include: symmetric, asymmetric,         │
      │   hashing, signatures, file encryption, and          │
      │   file sharing                                       │
      │ • Helps identify most active security users          │
      │ • Can be used for user performance tracking          │
      └──────────────────────────────────────────────────────┘

      ┌──────────────────────────────────────────────────────┐
      ║ 📊 NEW USER REGISTRATIONS OVER TIME                  ║
      ├──────────────────────────────────────────────────────┤
      │ • Displays user registration trends over last 30 days│
      │ • Shows daily new user counts                        │
      │ • Helps track platform growth                        │
      │ • Identifies registration spikes                     │
      │ • Useful for monitoring marketing effectiveness      │
      └──────────────────────────────────────────────────────┘

      ┌──────────────────────────────────────────────────────┐
      ║ 🥧 ACTIVE VS INACTIVE USERS                          ║
      ├──────────────────────────────────────────────────────┤
      │ • Pie chart showing user status distribution         │
      │ • Active = Users who can login currently             │
      │ • Inactive = Deactivated or suspended accounts       │
      │ • Provides quick overview of user base health        │
      │ • Helps identify account management needs            │
      └──────────────────────────────────────────────────────┘

      ┌──────────────────────────────────────────────────────┐
      ║ 🔥 LOGIN TIME PATTERNS (HEATMAP)                     ║
      ├──────────────────────────────────────────────────────┤
      │ • Shows login activity patterns                      │
      │ • X-axis: Hour of day (00:00 to 23:00)               │
      │ • Y-axis: Day of week (Monday to Sunday)             │
      │ • Color intensity indicates login frequency          │
      │ • Identifies peak usage times                        │
      │ • Helps with server load planning                    │
      └──────────────────────────────────────────────────────┘

      ╔══════════════════════════════════════════════════════╗
      ║                💡 ANALYTICS TIPS                     ║
      ╚══════════════════════════════════════════════════════╝

      1. 📅 Check registrations daily for growth trends
      2. 👥 Monitor active users for engagement
      3. 🔥 Use heatmap for peak load management
      4. 📈 Track top users for recognition programs
      5. 🔄 Refresh data for latest statistics
"""
        
        instructions_widget = tk.Text(instructions_frame, wrap=tk.WORD, height=35, width=70,
                                     bg='black', fg='#00ff00', font=('Courier', 9))
        instructions_widget.pack(fill='both', expand=True)
        instructions_widget.insert('1.0', instructions_text)
        instructions_widget.config(state='disabled')


        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def setup_security_monitoring_tab(self, parent):
        # Create a scrollable frame for security monitoring
        canvas = tk.Canvas(parent)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        # ✅ ADD SPLIT LAYOUT HERE (before counter tiles)
        main_container = ttk.Frame(scrollable_frame)
        main_container.pack(fill='both', expand=True)

        left_column = ttk.Frame(main_container)
        left_column.pack(side='left', fill='both', expand=True)

        right_instructions = ttk.Frame(main_container)
        right_instructions.pack(side='right', fill='y', padx=5)
        right_instructions.config(width=700)
        right_instructions.pack_propagate(False)
        
        # Counter tiles
        counters_frame = ttk.Frame(left_column)
        counters_frame.pack(fill='x', padx=10, pady=5)
        
        # Today's security events
        today_frame = ttk.LabelFrame(counters_frame, text="🛡️ Security Events Today", padding=10)
        today_frame.pack(side='left', fill='both', expand=True, padx=5)
        
        self.today_failed_logins = ttk.Label(today_frame, text="Failed Logins: 0", font=('Arial', 12))
        self.today_failed_logins.pack()
        self.today_brute_force = ttk.Label(today_frame, text="Brute Force: 0", font=('Arial', 12))
        self.today_brute_force.pack()
        self.today_failed_decrypts = ttk.Label(today_frame, text="Failed Decrypts: 0", font=('Arial', 12))
        self.today_failed_decrypts.pack()
        
        # Weekly security events
        week_frame = ttk.LabelFrame(counters_frame, text="📅 Security Events This Week", padding=10)
        week_frame.pack(side='left', fill='both', expand=True, padx=5)
        
        self.week_failed_logins = ttk.Label(week_frame, text="Failed Logins: 0", font=('Arial', 12))
        self.week_failed_logins.pack()
        self.week_brute_force = ttk.Label(week_frame, text="Brute Force: 0", font=('Arial', 12))
        self.week_brute_force.pack()
        self.week_failed_decrypts = ttk.Label(week_frame, text="Failed Decrypts: 0", font=('Arial', 12))
        self.week_failed_decrypts.pack()
        
        # Bar graph: Failed vs successful decrypt attempts
        decrypt_frame = ttk.LabelFrame(left_column, text="🔐 Decrypt Attempts Analysis", padding=10)
        decrypt_frame.pack(fill='x', padx=10, pady=5)

        self.decrypt_canvas_frame = ttk.Frame(decrypt_frame)
        self.decrypt_canvas_frame.pack(fill='both', expand=True)
        
        # Line graph: Brute-force / suspicious activity trend
        brute_frame = ttk.LabelFrame(left_column, text="📈 Suspicious Activity Trend", padding=10)
        brute_frame.pack(fill='x', padx=10, pady=5)
        
        self.brute_canvas_frame = ttk.Frame(brute_frame)
        self.brute_canvas_frame.pack(fill='both', expand=True)
        
        # Pie chart: Attack types detected
        attack_frame = ttk.LabelFrame(left_column, text="⚠️ Attack Types Distribution", padding=10)
        attack_frame.pack(fill='x', padx=10, pady=5)
        
        self.attack_canvas_frame = ttk.Frame(attack_frame)
        self.attack_canvas_frame.pack(fill='both', expand=True)
        
        # Recent suspicious activities
        activities_frame = ttk.LabelFrame(left_column, text="🚨 Recent Suspicious Activities", padding=10)
        activities_frame.pack(fill='x', padx=10, pady=5)
        
        self.activities_text = scrolledtext.ScrolledText(activities_frame, height=6, bg='black', fg='#00ff00', wrap=tk.WORD)
        self.activities_text.pack(fill='both', expand=True)
        self.activities_text.config(state='disabled')

        # Instructions for Security Monitoring (RIGHT COLUMN)
        instructions_frame = ttk.LabelFrame( right_instructions, text="📋 Security Monitoring Guide", padding=10)
        instructions_frame.pack(fill='both', expand=True, padx=5, pady=5)

        instructions_text = """
                ╔══════════════════════════════════════════════════════╗
                ║        🔒 SECURITY MONITORING DASHBOARD GUIDE        ║
                ╚══════════════════════════════════════════════════════╝

                ┌──────────────────────────────────────────────────────┐
                │ 🛡️ SECURITY EVENTS TODAY                             ║
                ├──────────────────────────────────────────────────────┤
                │ • Failed Logins: Unsuccessful login attempts today   │
                │ • Brute Force: Multiple failed attempts from same IP │
                │ • Failed Decrypts: Incorrect decryption attempts     │
                │ • Monitor for sudden spikes in failed attempts       │
                └──────────────────────────────────────────────────────┘

                ┌──────────────────────────────────────────────────────┐
                │ 📅 SECURITY EVENTS THIS WEEK                         ║
                ├──────────────────────────────────────────────────────┤
                │ • Weekly summary of security events                  │
                │ • Helps identify patterns over time                  │
                │ • Compare with daily stats for trends                │
                │ • Useful for weekly security reports                 │
                └──────────────────────────────────────────────────────┘

                ┌──────────────────────────────────────────────────────┐
                │ 🔐 DECRYPT ATTEMPTS ANALYSIS                         ║
                ├──────────────────────────────────────────────────────┤
                │ • Shows failed vs successful decrypt attempts        │
                │ • High failure rate may indicate:                    │
                │   - Incorrect keys/passwords                         │
                │   - Malformed encrypted data                         │
                │   - Potential attack attempts                        │
                │ • Success rate indicates system reliability          │
                └──────────────────────────────────────────────────────┘

                ┌──────────────────────────────────────────────────────┐
                │ 📈 SUSPICIOUS ACTIVITY TREND                         ║
                ├──────────────────────────────────────────────────────┤
                │ • Shows brute-force attempts over last 7 days        │
                │ • Identifies attack patterns                         │
                │ • Peaks indicate coordinated attacks                 │
                │ • Helps in proactive defense planning                │
                └──────────────────────────────────────────────────────┘

                ┌──────────────────────────────────────────────────────┐
                │ ⚠️ ATTACK TYPES DISTRIBUTION                         ║
                ├──────────────────────────────────────────────────────┤
                │ • Brute Force: Password guessing attacks             │
                │ • Invalid Format: Malformed data attacks             │
                │ • Unauthorized Access: Permission violations         │
                │ • Malformed Data: Corrupted input attacks            │
                │ • Distribution helps prioritize security fixes       │
                └──────────────────────────────────────────────────────┘

                ┌──────────────────────────────────────────────────────┐
                │ 🚨 RECENT SUSPICIOUS ACTIVITIES                      ║
                ├──────────────────────────────────────────────────────┤
                │ • Real-time log of security events                   │
                │ • Timestamped entries                                │
                │ • Shows event type and details                       │
                │ • Last 10 activities displayed                       │
                └──────────────────────────────────────────────────────┘

                ╔══════════════════════════════════════════════════════╗
                ║                🚨 SECURITY ALERTS                    ║
                ╚══════════════════════════════════════════════════════╝

                ⚠️ IMMEDIATE ACTION REQUIRED IF:
                • >50 failed logins in 1 hour
                • >20 brute force attempts in 1 day
                • Multiple failed decrypts from same user
                • Unusual login patterns in heatmap

                ✅ RECOMMENDED ACTIONS:
                1. Review failed login sources
                2. Check for compromised accounts
                3. Update security policies
                4. Enable 2FA for sensitive accounts
                5. Regular security audits
"""
        
        instructions_widget = tk.Text(instructions_frame, wrap=tk.WORD, height=40, width=50,
                                     bg='black', fg='#00ff00', font=('Courier', 9))
        instructions_widget.pack(fill='both', expand=True)
        instructions_widget.insert('1.0', instructions_text)
        instructions_widget.config(state='disabled')

        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
    
    def refresh_data(self):
        # Clear existing plots
        for widget in self.bar_canvas_frame.winfo_children():
            widget.destroy()
        for widget in self.line_canvas_frame.winfo_children():
            widget.destroy()
        for widget in self.pie_canvas_frame.winfo_children():
            widget.destroy()
        for widget in self.heatmap_canvas_frame.winfo_children():
            widget.destroy()
        for widget in self.decrypt_canvas_frame.winfo_children():
            widget.destroy()
        for widget in self.brute_canvas_frame.winfo_children():
            widget.destroy()
        for widget in self.attack_canvas_frame.winfo_children():
            widget.destroy()
        
        # Get data
        users = self.user_manager.get_all_users()
        security_stats = self.security_monitor.get_security_stats()
        
        # 1. Bar graph: Top users by encrypted files
        user_operations = []
        for email, data in users.items():
            ops = data.get('encryption_operations', {})
            total_ops = sum(ops.values())
            user_operations.append((data.get('username', email), total_ops))
        
        user_operations.sort(key=lambda x: x[1], reverse=True)
        top_users = user_operations[:5]
        
        if top_users:
            fig1 = Figure(figsize=(6, 3), dpi=80)
            ax1 = fig1.add_subplot(111)
            names = [user[0][:15] + '...' if len(user[0]) > 15 else user[0] for user in top_users]
            values = [user[1] for user in top_users]
            bars = ax1.bar(names, values, color=['#3498db', '#2ecc71', '#e74c3c', '#f39c12', '#9b59b6'])
            ax1.set_title('Top 5 Users by Encryption Operations')
            ax1.set_ylabel('Number of Operations')
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}', ha='center', va='bottom')
            
            canvas1 = FigureCanvasTkAgg(fig1, self.bar_canvas_frame)
            canvas1.draw()
            canvas1.get_tk_widget().pack(fill='both', expand=True)
        
        # 2. Line graph: New user registrations over time
        if users:
            # Group by registration date
            reg_dates = {}
            for email, data in users.items():
                reg_date = datetime.fromtimestamp(data.get('created_at', time.time())).strftime('%Y-%m-%d')
                reg_dates[reg_date] = reg_dates.get(reg_date, 0) + 1
            
            # Sort dates and get last 30 days
            sorted_dates = sorted(reg_dates.items())
            if len(sorted_dates) > 30:
                sorted_dates = sorted_dates[-30:]
            
            if sorted_dates:
                fig2 = Figure(figsize=(6, 3), dpi=80)
                ax2 = fig2.add_subplot(111)
                dates = [date[0] for date in sorted_dates]
                counts = [date[1] for date in sorted_dates]
                ax2.plot(dates, counts, marker='o', color='#e74c3c', linewidth=2)
                ax2.set_title('New User Registrations (Last 30 Days)')
                ax2.set_ylabel('Number of Users')
                ax2.set_xlabel('Date')
                ax2.grid(True, alpha=0.3)
                plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45)
                
                canvas2 = FigureCanvasTkAgg(fig2, self.line_canvas_frame)
                canvas2.draw()
                canvas2.get_tk_widget().pack(fill='both', expand=True)
        
        # 3. Pie chart: Active vs inactive users
        if users:
            active = sum(1 for u in users.values() if u.get('active', True))
            inactive = len(users) - active
            
            fig3 = Figure(figsize=(5, 3), dpi=80)
            ax3 = fig3.add_subplot(111)
            sizes = [active, inactive]
            labels = ['Active', 'Inactive']
            colors = ['#2ecc71', '#e74c3c']
            
            if sum(sizes) > 0:
                ax3.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
                ax3.set_title('User Status Distribution')
                
                canvas3 = FigureCanvasTkAgg(fig3, self.pie_canvas_frame)
                canvas3.draw()
                canvas3.get_tk_widget().pack(fill='both', expand=True)
        
        # 4. Heatmap: Login time patterns (simulated data)
        fig4 = Figure(figsize=(5, 3), dpi=80)
        ax4 = fig4.add_subplot(111)
        
        # Generate sample data for heatmap
        days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        hours = [f'{h:02d}:00' for h in range(24)]
        
        # Create random login pattern data
        np.random.seed(42)
        data = np.random.rand(len(days), len(hours))
        
        # Make weekdays and business hours more active
        for i, day in enumerate(days):
            if i < 5:  # Weekdays
                for j in range(9, 17):  # Business hours
                    data[i, j] += 0.5  # Increase activity
        
        im = ax4.imshow(data, cmap='YlOrRd', aspect='auto')
        ax4.set_xticks(range(len(hours)))
        ax4.set_xticklabels([h.split(':')[0] for h in hours], rotation=90, fontsize=6)
        ax4.set_yticks(range(len(days)))
        ax4.set_yticklabels(days)
        ax4.set_title('Login Activity Heatmap (Hour vs Day)')
        ax4.set_xlabel('Hour of Day')
        ax4.set_ylabel('Day of Week')
        
        fig4.colorbar(im, ax=ax4)
        
        canvas4 = FigureCanvasTkAgg(fig4, self.heatmap_canvas_frame)
        canvas4.draw()
        canvas4.get_tk_widget().pack(fill='both', expand=True)
        
        # 5. Security: Failed vs successful decrypt attempts
        fig5 = Figure(figsize=(6, 3), dpi=80)
        ax5 = fig5.add_subplot(111)
        
        categories = ['Failed Decrypts', 'Successful Decrypts']
        values = [security_stats.get('failed_decrypts', 0), 
                 security_stats.get('successful_decrypts', 0)]
        colors = ['#e74c3c', '#2ecc71']
        
        bars = ax5.bar(categories, values, color=colors)
        ax5.set_title('Decrypt Attempts Analysis')
        ax5.set_ylabel('Number of Attempts')
        
        # Add value labels
        for bar in bars:
            height = bar.get_height()
            ax5.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom')
        
        canvas5 = FigureCanvasTkAgg(fig5, self.decrypt_canvas_frame)
        canvas5.draw()
        canvas5.get_tk_widget().pack(fill='both', expand=True)
        
        # 6. Security: Brute-force trend (simulated weekly data)
        fig6 = Figure(figsize=(6, 3), dpi=80)
        ax6 = fig6.add_subplot(111)
        
        # Generate sample weekly data
        days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        brute_data = np.random.randint(0, 20, size=7)
        
        ax6.plot(days, brute_data, marker='o', color='#e74c3c', linewidth=2)
        ax6.fill_between(days, brute_data, alpha=0.3, color='#e74c3c')
        ax6.set_title('Weekly Brute-force Attempt Trend')
        ax6.set_ylabel('Number of Attempts')
        ax6.set_xlabel('Day of Week')
        ax6.grid(True, alpha=0.3)
        
        canvas6 = FigureCanvasTkAgg(fig6, self.brute_canvas_frame)
        canvas6.draw()
        canvas6.get_tk_widget().pack(fill='both', expand=True)
        
        # 7. Security: Attack types distribution
        fig7 = Figure(figsize=(5, 3), dpi=80)
        ax7 = fig7.add_subplot(111)
        
        attack_types = security_stats.get('attack_types', {})
        if attack_types:
            labels = list(attack_types.keys())
            sizes = list(attack_types.values())
            colors = ['#e74c3c', '#f39c12', '#3498db', '#9b59b6']
            
            if sum(sizes) > 0:
                ax7.pie(sizes, labels=labels, colors=colors[:len(labels)], 
                       autopct='%1.1f%%', startangle=90)
                ax7.set_title('Attack Types Distribution')
                
                canvas7 = FigureCanvasTkAgg(fig7, self.attack_canvas_frame)
                canvas7.draw()
                canvas7.get_tk_widget().pack(fill='both', expand=True)
        
        # Update counter tiles
        today_stats = security_stats.get('today_stats', {})
        weekly_stats = security_stats.get('weekly_stats', {})
        
        self.today_failed_logins.config(text=f"Failed Logins: {today_stats.get('failed_logins', 0)}")
        self.today_brute_force.config(text=f"Brute Force: {today_stats.get('brute_force_attempts', 0)}")
        self.today_failed_decrypts.config(text=f"Failed Decrypts: {today_stats.get('failed_decrypts', 0)}")
        
        self.week_failed_logins.config(text=f"Failed Logins: {weekly_stats.get('failed_logins', 0)}")
        self.week_brute_force.config(text=f"Brute Force: {weekly_stats.get('brute_force_attempts', 0)}")
        self.week_failed_decrypts.config(text=f"Failed Decrypts: {weekly_stats.get('failed_decrypts', 0)}")
        
        # Update recent activities
        self.activities_text.config(state='normal')
        self.activities_text.delete('1.0', tk.END)
        
        activities = security_stats.get('suspicious_activities', [])
        if activities:
            for activity in activities[-5:]:  # Show last 5 activities
                timestamp = datetime.fromtimestamp(activity.get('timestamp', time.time())).strftime('%Y-%m-%d %H:%M:%S')
                event_type = activity.get('type', 'Unknown')
                details = activity.get('details', '')
                self.activities_text.insert(tk.END, f"[{timestamp}] {event_type}: {details}\n")
        else:
            self.activities_text.insert(tk.END, "No suspicious activities detected.\n")
        
        self.activities_text.config(state='disabled')
    
    def destroy(self):
        self.frame.destroy()

class AdminPanel:
    def __init__(self, parent, user_manager, show_dashboard_callback, security_monitor):
        self.parent = parent
        self.user_manager = user_manager
        self.security_monitor = security_monitor
        self.show_dashboard_callback = show_dashboard_callback
        self.frame = ttk.Frame(parent)
        self.frame.pack(fill='both', expand=True, padx=10, pady=10)
        self.setup_ui()
        self.refresh_data()
    
    def setup_ui(self):
        # Title
        title = ttk.Label(self.frame, text="🔐 Admin Dashboard", font=('Arial', 18, 'bold'))
        title.pack(pady=10)
        
        # Back button
        back_btn = ttk.Button(self.frame, text="← Back to Dashboard", 
                             command=self.show_dashboard_callback)
        back_btn.pack(anchor='nw', padx=10, pady=5)
        
        # Create notebook for different admin sections
        notebook = ttk.Notebook(self.frame)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # User Management Tab
        user_tab = ttk.Frame(notebook)
        notebook.add(user_tab, text="👥 User Management")
        self.setup_user_management_tab(user_tab)
        
        # Analytics Tab
        analytics_tab = ttk.Frame(notebook)
        notebook.add(analytics_tab, text="📊 Analytics")
        self.analytics_dashboard = AnalyticsDashboard(analytics_tab, self.user_manager, self.security_monitor)
        
        # System Info Tab
        info_tab = ttk.Frame(notebook)
        notebook.add(info_tab, text="⚙️ System Info")
        self.setup_system_info_tab(info_tab)
    
    def setup_user_management_tab(self, parent):
        # Stats frame
        stats_frame = ttk.LabelFrame(parent, text="System Statistics", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack()
        
        stats_data = [
            ('Total Users:', 'total_users'),
            ('Active Users:', 'active_users'),
            ('Admin Users:', 'admin_users'),
            ('Total Logins:', 'total_logins'),
            ('Recent (24h):', 'recent_users'),
            ('Locked Users:', 'locked_users')
        ]
        
        for i, (label_text, key) in enumerate(stats_data):
            frame = ttk.Frame(stats_grid)
            frame.grid(row=i//3, column=i%3, padx=20, pady=5, sticky='w')
            ttk.Label(frame, text=label_text, font=('Arial', 10)).pack(side='left')
            self.stats_labels[key] = ttk.Label(frame, text="0", font=('Arial', 10, 'bold'))
            self.stats_labels[key].pack(side='left', padx=(5,0))
        
        # Control buttons
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill='x', pady=10, padx=10)
        
        ttk.Button(control_frame, text="🔄 Refresh", command=self.refresh_data).pack(side='left', padx=5)
        ttk.Button(control_frame, text="📊 Export CSV", command=self.export_users_csv).pack(side='left', padx=5)
        ttk.Button(control_frame, text="📋 Generate Report", command=self.generate_report).pack(side='left', padx=5)
        
        # User management frame
        user_frame = ttk.LabelFrame(parent, text="User Management", padding=10)
        user_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Treeview for users
        columns = ('Email', 'Username', 'Admin', 'Status', 'Logins', 'Last Login', 'Created')
        self.tree = ttk.Treeview(user_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, minwidth=50)
        
        self.tree.column('Email', width=200)
        self.tree.column('Last Login', width=150)
        
        # Scrollbars
        vsb = ttk.Scrollbar(user_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(user_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        user_frame.grid_rowconfigure(0, weight=1)
        user_frame.grid_columnconfigure(0, weight=1)
        
        # User action buttons
        action_frame = ttk.Frame(user_frame)
        action_frame.grid(row=2, column=0, columnspan=2, pady=10, sticky='ew')
        
        ttk.Button(action_frame, text="🗑️ Delete User", command=self.delete_selected_user).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🔄 Toggle Status", command=self.toggle_user_status).pack(side='left', padx=5)
        ttk.Button(action_frame, text="⬆️ Promote to Admin", command=self.promote_user).pack(side='left', padx=5)
        ttk.Button(action_frame, text="⬇️ Demote from Admin", command=self.demote_user).pack(side='left', padx=5)
        ttk.Button(action_frame, text="👁️ View Details", command=self.view_user_details).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🔓 Unlock User", command=self.unlock_user).pack(side='left', padx=5)
    
    def setup_system_info_tab(self, parent):
        # System information
        info_frame = ttk.LabelFrame(parent, text="System Information", padding=15)
        info_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        info_text = scrolledtext.ScrolledText(info_frame, wrap=tk.WORD, height=15)
        info_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Get system info
        import platform
        import psutil
        
        system_info = f"""
=== SYSTEM INFORMATION ===

Platform: {platform.platform()}
Python Version: {platform.python_version()}
System: {platform.system()} {platform.release()}
Processor: {platform.processor()}

=== RESOURCE USAGE ===
CPU Usage: {psutil.cpu_percent()}%
Memory Usage: {psutil.virtual_memory().percent}%
Disk Usage: {psutil.disk_usage('/').percent}%

=== SECURITY STATUS ===
Encryption Suite: v2.0
Last Security Audit: {datetime.now().strftime('%Y-%m-%d')}
Default Admin: Configured
User Database: SQLite
Security Logs: JSONL format

=== RECOMMENDATIONS ===
1. Regularly backup user database
2. Review failed login attempts
3. Monitor suspicious activities
4. Update encryption keys periodically

=== SUPPORT ===
For technical support contact:
Email: support@encryption.suite
Documentation: Available in help menu
"""
        
        info_text.insert('1.0', system_info)
        info_text.config(state='disabled')
        
        # System action buttons
        action_frame = ttk.Frame(parent)
        action_frame.pack(pady=10)
        
        ttk.Button(action_frame, text="🔄 Check System Health", 
                  command=self.check_system_health).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🗃️ Backup Database", 
                  command=self.backup_database).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🧹 Clear Logs", 
                  command=self.clear_logs).pack(side='left', padx=5)
    
    def refresh_data(self):
        stats = self.user_manager.get_system_stats()
        for key, value in stats.items():
            if key in self.stats_labels:
                self.stats_labels[key].config(text=str(value))
        
        if hasattr(self, 'tree'):
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            users = self.user_manager.get_all_users()
            for email, user_data in users.items():
                last_login = user_data.get('last_login')
                if last_login:
                    last_login_str = datetime.fromtimestamp(last_login).strftime('%Y-%m-%d %H:%M')
                else:
                    last_login_str = 'Never'
                
                created = datetime.fromtimestamp(user_data.get('created_at', time.time())).strftime('%Y-%m-%d')
                
                # Check if user is locked
                status = 'Active' if user_data.get('active', True) else 'Inactive'
                if email in self.user_manager.login_attempts:
                    attempts = self.user_manager.login_attempts[email]
                    if attempts.get('attempts', 0) >= 3:
                        lockout_time = attempts.get('lockout_until', 0)
                        if time.time() < lockout_time:
                            status = 'Locked'
                
                values = (
                    email,
                    user_data.get('username', 'N/A'),
                    'Yes' if user_data.get('is_admin', False) else 'No',
                    status,
                    str(user_data.get('login_count', 0)),
                    last_login_str,
                    created
                )
                self.tree.insert('', 'end', values=values, iid=email)
        
        # Refresh analytics if available
        if hasattr(self, 'analytics_dashboard'):
            self.analytics_dashboard.refresh_data()
    
    def get_selected_user(self):
        if hasattr(self, 'tree'):
            selection = self.tree.selection()
            if selection:
                return selection[0]
        return None
    
    def delete_selected_user(self):
        email = self.get_selected_user()
        if not email:
            messagebox.showwarning("No Selection", "Please select a user first")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete user:\n{email}?"):
            success, message = self.user_manager.delete_user(email)
            if success:
                messagebox.showinfo("Success", message)
                self.refresh_data()
            else:
                messagebox.showerror("Error", message)
    
    def toggle_user_status(self):
        email = self.get_selected_user()
        if not email:
            messagebox.showwarning("No Selection", "Please select a user first")
            return
        
        users = self.user_manager.get_all_users()
        if email in users:
            current_status = users[email].get('active', True)
            new_status = not current_status
            
            success, message = self.user_manager.toggle_user_status(email, new_status)
            if success:
                status = "activated" if new_status else "deactivated"
                messagebox.showinfo("Success", f"User {status} successfully")
                self.refresh_data()
            else:
                messagebox.showerror("Error", message)
    
    def promote_user(self):
        email = self.get_selected_user()
        if not email:
            messagebox.showwarning("No Selection", "Please select a user first")
            return
        
        success, message = self.user_manager.promote_to_admin(email)
        if success:
            messagebox.showinfo("Success", message)
            self.refresh_data()
        else:
            messagebox.showerror("Error", message)
    
    def demote_user(self):
        email = self.get_selected_user()
        if not email:
            messagebox.showwarning("No Selection", "Please select a user first")
            return
        
        success, message = self.user_manager.demote_from_admin(email)
        if success:
            messagebox.showinfo("Success", message)
            self.refresh_data()
        else:
            messagebox.showerror("Error", message)
    
    def unlock_user(self):
        email = self.get_selected_user()
        if not email:
            messagebox.showwarning("No Selection", "Please select a user first")
            return
        
        if email in self.user_manager.login_attempts:
            self.user_manager.login_attempts.pop(email)
            messagebox.showinfo("Success", f"User {email} unlocked successfully")
            self.refresh_data()
        else:
            messagebox.showinfo("Info", "User is not locked")
    
    def view_user_details(self):
        email = self.get_selected_user()
        if not email:
            messagebox.showwarning("No Selection", "Please select a user first")
            return
        
        users = self.user_manager.get_all_users()
        if email in users:
            user_data = users[email]
            
            details_window = tk.Toplevel(self.parent)
            details_window.title(f"User Details - {email}")
            details_window.geometry("500x450")
            
            text_area = scrolledtext.ScrolledText(details_window, wrap=tk.WORD, width=60, height=22)
            text_area.pack(padx=10, pady=10, fill='both', expand=True)
            
            # Check lock status
            lock_status = "Not locked"
            if email in self.user_manager.login_attempts:
                attempts = self.user_manager.login_attempts[email]
                lock_status = f"Locked ({attempts.get('attempts', 0)} failed attempts)"
            
            details = f"""
EMAIL: {email}
USERNAME: {user_data.get('username', 'N/A')}
ADMIN: {'Yes' if user_data.get('is_admin', False) else 'No'}
STATUS: {'Active' if user_data.get('active', True) else 'Inactive'}
LOCK STATUS: {lock_status}

--- STATISTICS ---
Login Count: {user_data.get('login_count', 0)}
Failed Attempts: {user_data.get('failed_attempts', 0)}
Created: {datetime.fromtimestamp(user_data.get('created_at', 0)).strftime('%Y-%m-%d %H:%M:%S')}
Last Login: {datetime.fromtimestamp(user_data.get('last_login', 0)).strftime('%Y-%m-%d %H:%M:%S') if user_data.get('last_login') else 'Never'}

--- ENCRYPTION OPERATIONS ---
Symmetric Operations: {user_data.get('encryption_operations', {}).get('symmetric', 0)}
Asymmetric Operations: {user_data.get('encryption_operations', {}).get('asymmetric', 0)}
Hashing Operations: {user_data.get('encryption_operations', {}).get('hashing', 0)}
Signature Operations: {user_data.get('encryption_operations', {}).get('signatures', 0)}
File Encryption Operations: {user_data.get('encryption_operations', {}).get('file_encryption', 0)}
File Sharing Operations: {user_data.get('encryption_operations', {}).get('file_sharing', 0)}
TOTAL OPERATIONS: {sum(user_data.get('encryption_operations', {}).values())}
"""
            
            text_area.insert('1.0', details)
            text_area.config(state='disabled')
    
    def export_users_csv(self):
        users = self.user_manager.get_all_users()
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['email', 'username', 'is_admin', 'active', 'login_count', 'failed_attempts', 'last_login', 'created_at']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for email, user_data in users.items():
                    writer.writerow({
                        'email': email,
                        'username': user_data.get('username', ''),
                        'is_admin': user_data.get('is_admin', False),
                        'active': user_data.get('active', True),
                        'login_count': user_data.get('login_count', 0),
                        'failed_attempts': user_data.get('failed_attempts', 0),
                        'last_login': user_data.get('last_login', ''),
                        'created_at': user_data.get('created_at', '')
                    })
            
            messagebox.showinfo("Success", f"Users exported to {filename}")
    
    def generate_report(self):
        users = self.user_manager.get_all_users()
        security_stats = self.security_monitor.get_security_stats()
        
        report_window = tk.Toplevel(self.parent)
        report_window.title("System Report")
        report_window.geometry("500x400")
        
        text_area = scrolledtext.ScrolledText(report_window, wrap=tk.WORD, width=60, height=20)
        text_area.pack(padx=10, pady=10, fill='both', expand=True)
        
        total_users = len(users)
        active_users = sum(1 for u in users.values() if u.get('active', True))
        admin_users = sum(1 for u in users.values() if u.get('is_admin', False))
        total_logins = sum(u.get('login_count', 0) for u in users.values())
        
        symmetric_ops = sum(u.get('encryption_operations', {}).get('symmetric', 0) for u in users.values())
        asymmetric_ops = sum(u.get('encryption_operations', {}).get('asymmetric', 0) for u in users.values())
        hashing_ops = sum(u.get('encryption_operations', {}).get('hashing', 0) for u in users.values())
        signature_ops = sum(u.get('encryption_operations', {}).get('signatures', 0) for u in users.values())
        file_enc_ops = sum(u.get('encryption_operations', {}).get('file_encryption', 0) for u in users.values())
        file_share_ops = sum(u.get('encryption_operations', {}).get('file_sharing', 0) for u in users.values())
        
        report = f"""
=== ENCRYPTION SUITE SYSTEM REPORT ===
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

--- USER STATISTICS ---
Total Users: {total_users}
Active Users: {active_users}
Admin Users: {admin_users}
Inactive Users: {total_users - active_users}
Total Login Count: {total_logins}

--- OPERATION STATISTICS ---
Symmetric Operations: {symmetric_ops}
Asymmetric Operations: {asymmetric_ops}
Hashing Operations: {hashing_ops}
Signature Operations: {signature_ops}
File Encryption Operations: {file_enc_ops}
File Sharing Operations: {file_share_ops}
TOTAL OPERATIONS: {symmetric_ops + asymmetric_ops + hashing_ops + signature_ops + file_enc_ops + file_share_ops}

--- SECURITY STATISTICS ---
Failed Logins: {security_stats.get('failed_logins', 0)}
Successful Logins: {security_stats.get('successful_logins', 0)}
Failed Decrypts: {security_stats.get('failed_decrypts', 0)}
Successful Decrypts: {security_stats.get('successful_decrypts', 0)}
Brute Force Attempts: {security_stats.get('brute_force_attempts', 0)}

--- SYSTEM HEALTH ---
Database: SQLite
Default Admin: {'Configured' if 'admin@encryption.suite' in users else 'Missing'}
Security Logs: {'JSONL format' if security_stats else 'Inactive'}
"""
        
        text_area.insert('1.0', report)
        text_area.config(state='disabled')
    
    def check_system_health(self):
        users = self.user_manager.get_all_users()
        security_stats = self.security_monitor.get_security_stats()
        
        issues = []
        
        # Check for issues
        if len(users) == 0:
            issues.append("⚠️ No users in database")
        
        if 'admin@encryption.suite' not in users:
            issues.append("⚠️ Default admin account missing")
        
        failed_logins = security_stats.get('failed_logins', 0)
        if failed_logins > 100:
            issues.append(f"⚠️ High number of failed logins: {failed_logins}")
        
        brute_force = security_stats.get('brute_force_attempts', 0)
        if brute_force > 50:
            issues.append(f"⚠️ High brute force activity: {brute_force} attempts")
        
        # Check for locked users
        locked_count = sum(1 for email in self.user_manager.login_attempts 
                          if self.user_manager.login_attempts[email].get('attempts', 0) >= 3)
        if locked_count > 0:
            issues.append(f"⚠️ {locked_count} user(s) currently locked out")
        
        if not issues:
            messagebox.showinfo("System Health", "✅ All systems are functioning normally.")
        else:
            issues_text = "\n".join(issues)
            messagebox.showwarning("System Health", 
                                 f"System check completed with issues:\n\n{issues_text}")
    
    def backup_database(self):
        import shutil
        import datetime
        
        backup_dir = "backups"
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"backup_{timestamp}.zip")
        
        try:
            with zipfile.ZipFile(backup_file, 'w') as zipf:
                # Backup user database
                if os.path.exists('encryption_suite.db'):
                    zipf.write('encryption_suite.db', 'encryption_suite.db')
                
                # Backup shared files database
                if os.path.exists('shared_files.json'):
                    zipf.write('shared_files.json', 'shared_files.json')
                
                # Backup security logs
                if os.path.exists('security_logs.jsonl'):
                    zipf.write('security_logs.jsonl', 'security_logs.jsonl')
            
            messagebox.showinfo("Backup Successful", 
                              f"Database backed up to:\n{backup_file}")
        except Exception as e:
            messagebox.showerror("Backup Failed", f"Failed to create backup: {str(e)}")
    
    def clear_logs(self):
        if messagebox.askyesno("Confirm Clear", 
                              "Are you sure you want to clear all security logs?\nThis action cannot be undone."):
            try:
                with open('security_logs.jsonl', 'w') as f:
                    pass  # Create empty file
                
                messagebox.showinfo("Success", "Security logs cleared successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear logs: {str(e)}")
    
    def destroy(self):
        self.frame.destroy()

class ModernTkinterGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔐 Cryptex Share - A Multi-Encryption Platform")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        self.user_manager = UserManager()
        self.file_sharing = FileSharingManager()
        self.security_monitor = SecurityMonitor()
        self.current_frame = None
        self.admin_panel = None
        
        self.setup_styles()
        self.setup_main_window()
    
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('Title.TLabel', 
                       background='#2c3e50', 
                       foreground='#ecf0f1', 
                       font=('Arial', 16, 'bold'))
        
        style.configure('Card.TFrame', 
                       background='#34495e', 
                       relief='raised', 
                       borderwidth=1)
        
        style.configure('Modern.TButton',
                       background='#3498db',
                       foreground='white',
                       borderwidth=0,
                       focuscolor='none',
                       font=('Arial', 10),
                       padding=(20, 10))
        
        style.map('Modern.TButton',
                 background=[('active', '#2980b9')])
        
        style.configure('Admin.TButton',
                       background='#e74c3c',
                       foreground='white',
                       borderwidth=0,
                       font=('Arial', 10, 'bold'),
                       padding=(20, 10))
        
        style.map('Admin.TButton',
                 background=[('active', '#c0392b')])
        
        style.configure('Danger.TButton',
                       background='#e74c3c',
                       foreground='white',
                       font=('Arial', 10))
        
        style.map('Danger.TButton',
                 background=[('active', '#c0392b')])
        
        style.configure('Success.TButton',
                       background='#2ecc71',
                       foreground='white',
                       font=('Arial', 10))
        
        style.map('Success.TButton',
                 background=[('active', '#27ae60')])
        
        style.configure('Warning.TButton',
                       background='#f39c12',
                       foreground='white',
                       font=('Arial', 10))
        
        style.map('Warning.TButton',
                 background=[('active', '#e67e22')])
    
    def setup_main_window(self):
        if self.user_manager.current_user:
            self.show_dashboard()
        else:
            self.show_auth_frame()
    
    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()
            self.current_frame = None
        
        if self.admin_panel:
            self.admin_panel.destroy()
            self.admin_panel = None
    
    def show_auth_frame(self):
        self.clear_frame()
        self.current_frame = ttk.Frame(self.root, style='Card.TFrame')
        self.current_frame.pack(fill='both', expand=True, padx=50, pady=50)
        
        title = ttk.Label(self.current_frame, text="🔐 Cryptex Share", style='Title.TLabel')
        title.pack(pady=20)
        
        notebook = ttk.Notebook(self.current_frame)
        notebook.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Login Frame
        login_frame = ttk.Frame(notebook, style='Card.TFrame')
        notebook.add(login_frame, text='Login')
        
        ttk.Label(login_frame, text="Email/Username:").pack(pady=5)
        login_ident = ttk.Entry(login_frame, width=30)
        login_ident.pack(pady=5)
        
        ttk.Label(login_frame, text="Password:").pack(pady=5)
        login_pass = ttk.Entry(login_frame, show='*', width=30)
        login_pass.pack(pady=5)
        
        # Login attempts info
        self.login_attempts_label = ttk.Label(login_frame, text="", font=('Arial', 9), foreground='red')
        self.login_attempts_label.pack(pady=5)
        
        # Admin login hint
        ttk.Label(login_frame, text="Developer 👨‍💻 ®️❓", 
                 font=('Arial', 8), foreground='gray').pack(pady=5)
        
        login_btn = ttk.Button(login_frame, text="Login", style='Modern.TButton',
                              command=lambda: self.handle_login(login_ident.get(), login_pass.get()))
        login_btn.pack(pady=20)
        
        # Register Frame
        register_frame = ttk.Frame(notebook, style='Card.TFrame')
        notebook.add(register_frame, text='Register')
        
        ttk.Label(register_frame, text="Email:").pack(pady=5)
        reg_email = ttk.Entry(register_frame, width=30)
        reg_email.pack(pady=5)
        
        ttk.Label(register_frame, text="Username:").pack(pady=5)
        reg_user = ttk.Entry(register_frame, width=30)
        reg_user.pack(pady=5)
        
        ttk.Label(register_frame, text="Password:").pack(pady=5)
        reg_pass = ttk.Entry(register_frame, show='*', width=30)
        reg_pass.pack(pady=5)
        
        ttk.Label(register_frame, text="Confirm Password:").pack(pady=5)
        reg_conf = ttk.Entry(register_frame, show='*', width=30)
        reg_conf.pack(pady=5)
        
        register_btn = ttk.Button(register_frame, text="Register", style='Modern.TButton',
                                 command=lambda: self.handle_register(
                                     reg_email.get(), reg_user.get(), reg_pass.get(), reg_conf.get()))
        register_btn.pack(pady=20)
    
    def handle_login(self, identifier, password):
        if not identifier or not password:
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        success, message = self.user_manager.login(identifier, password)
        if success:
            self.security_monitor.log_event('successful_login', {'user': identifier})
            messagebox.showinfo("Success", message)
            self.show_dashboard()
        else:
            self.security_monitor.log_event('failed_login', {'user': identifier})
            
            # Update login attempts display
            if "attempts remaining" in message:
                self.login_attempts_label.config(text=message, foreground='orange')
            elif "locked" in message.lower():
                self.login_attempts_label.config(text=message, foreground='red')
                # Log brute force attempt
                self.security_monitor.log_event('brute_force', {'user': identifier})
            else:
                self.login_attempts_label.config(text="", foreground='red')
            
            messagebox.showerror("Error", message)
    
    def handle_register(self, email, username, password, confirm_password):
        if not all([email, username, password, confirm_password]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        success, message = self.user_manager.register(email, username, password, confirm_password, is_admin=False)
        if success:
            messagebox.showinfo("Success", message)
            self.show_auth_frame()
        else:
            messagebox.showerror("Error", message)
    
    def show_dashboard(self):
        self.clear_frame()
        self.current_frame = ttk.Frame(self.root)
        self.current_frame.pack(fill='both', expand=True)
        
        # Header
        header = ttk.Frame(self.current_frame, style='Card.TFrame')
        header.pack(fill='x', padx=20, pady=10)
        
        user_info = ttk.Label(header, 
                            text=f"👤 {self.user_manager.current_user['username']}", 
                            style='Title.TLabel')
        user_info.pack(side='left', padx=10)
        
        if self.user_manager.current_user['is_admin']:
            admin_label = ttk.Label(header, text="ADMIN", 
                                   style='Admin.TButton')
            admin_label.pack(side='left', padx=5)
        
        # Buttons
        btn_frame = ttk.Frame(header)
        btn_frame.pack(side='right', padx=10)
        
        if self.user_manager.current_user['is_admin']:
            admin_btn = ttk.Button(btn_frame, text="Admin Panel", style='Admin.TButton',
                                  command=self.show_admin_panel)
            admin_btn.pack(side='left', padx=5)
        
        logout_btn = ttk.Button(btn_frame, text="Logout", style='Danger.TButton',
                               command=self.handle_logout)
        logout_btn.pack(side='left', padx=5)
        
        # Main content notebook
        notebook = ttk.Notebook(self.current_frame)
        notebook.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Create all tabs
        self.create_symmetric_tab(notebook)
        self.create_asymmetric_tab(notebook)
        self.create_hashing_tab(notebook)
        self.create_hybrid_tab(notebook)
        self.create_file_encryption_tab(notebook)
    
    def show_admin_panel(self):
        self.clear_frame()
        self.admin_panel = AdminPanel(self.root, self.user_manager, self.show_dashboard, self.security_monitor)
    
    def handle_logout(self):
        self.user_manager.logout()
        self.show_auth_frame()
    
    def create_symmetric_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🔐 Symmetric Encryption")
        
        # Algorithm selection
        ttk.Label(frame, text="Algorithm:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        algo_var = tk.StringVar(value="AES")
        algo_combo = ttk.Combobox(frame, textvariable=algo_var, 
                                 values=["AES", "DES", "3DES", "ChaCha20"])
        algo_combo.grid(row=0, column=1, padx=5, pady=5)
        
        # Mode selection
        ttk.Label(frame, text="Mode:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        mode_var = tk.StringVar(value="CBC")
        mode_combo = ttk.Combobox(frame, textvariable=mode_var,
                                 values=["CBC", "CTR", "GCM"])
        mode_combo.grid(row=1, column=1, padx=5, pady=5)
        
        # Key and IV
        ttk.Label(frame, text="Key (Base64):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        key_entry = ttk.Entry(frame, width=50)
        key_entry.grid(row=2, column=1, padx=5, pady=5)
        
        ttk.Label(frame, text="IV (Base64):").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        iv_entry = ttk.Entry(frame, width=50)
        iv_entry.grid(row=3, column=1, padx=5, pady=5)
        
        # Generate key/IV button
        key_button_frame = ttk.Frame(frame)
        key_button_frame.grid(row=4, column=0, columnspan=2, pady=10)
        
        gen_btn = ttk.Button(key_button_frame, text="Generate Key/IV", style='Modern.TButton',
                            command=lambda: self.generate_symmetric_key(algo_var.get(), key_entry, iv_entry))
        gen_btn.pack(side='left', padx=5)
        
        # Add Clear button
        clear_btn = ttk.Button(key_button_frame, text="Clear Keys", style='Warning.TButton',
                              command=lambda: self.clear_symmetric_keys(key_entry, iv_entry))
        clear_btn.pack(side='left', padx=5)
        
        # Input text
        ttk.Label(frame, text="Input Text:").grid(row=5, column=0, padx=5, pady=5, sticky='nw')
        input_text = scrolledtext.ScrolledText(frame, width=50, height=5)
        input_text.grid(row=5, column=1, padx=5, pady=5)
        
        # Output text
        ttk.Label(frame, text="Output Text:").grid(row=6, column=0, padx=5, pady=5, sticky='nw')
        output_text = scrolledtext.ScrolledText(frame, width=50, height=5)
        output_text.grid(row=6, column=1, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=10)
        
        encrypt_btn = ttk.Button(button_frame, text="🔒 Encrypt", style='Modern.TButton',
                               command=lambda: self.symmetric_encrypt(
                                   algo_var.get(), mode_var.get(), 
                                   input_text.get('1.0', tk.END), 
                                   key_entry.get(), iv_entry.get(), output_text))
        encrypt_btn.pack(side='left', padx=5)
        
        decrypt_btn = ttk.Button(button_frame, text="🔓 Decrypt", style='Modern.TButton',
                               command=lambda: self.symmetric_decrypt(
                                   algo_var.get(), mode_var.get(),
                                   input_text.get('1.0', tk.END),
                                   key_entry.get(), iv_entry.get(), output_text))
        decrypt_btn.pack(side='left', padx=5)
        
        # Add Clear All button
        clear_all_btn = ttk.Button(button_frame, text="Clear All", style='Warning.TButton',
                                  command=lambda: self.clear_symmetric_all(input_text, output_text, key_entry, iv_entry))
        clear_all_btn.pack(side='left', padx=5)
    
    def clear_symmetric_keys(self, key_entry, iv_entry):
        key_entry.delete(0, tk.END)
        iv_entry.delete(0, tk.END)
    
    def clear_symmetric_all(self, input_text, output_text, key_entry, iv_entry):
        input_text.delete('1.0', tk.END)
        output_text.delete('1.0', tk.END)
        self.clear_symmetric_keys(key_entry, iv_entry)
    
    def generate_symmetric_key(self, algorithm, key_entry, iv_entry):
        key, iv = SymmetricCrypto.generate_key_iv(algorithm)
        key_entry.delete(0, tk.END)
        key_entry.insert(0, base64.b64encode(key).decode())
        iv_entry.delete(0, tk.END)
        iv_entry.insert(0, base64.b64encode(iv).decode())
    
    def symmetric_encrypt(self, algorithm, mode, text, key_b64, iv_b64, output_widget):
        try:
            if not text.strip():
                messagebox.showerror("Error", "Please enter text to encrypt")
                return
            
            key = base64.b64decode(key_b64) if key_b64 else None
            iv = base64.b64decode(iv_b64) if iv_b64 else None
            
            if not key:
                messagebox.showerror("Error", "Please generate or enter a key")
                return
            
            ciphertext = SymmetricCrypto.encrypt_text(algorithm, mode, text.strip(), key, iv)
            output_widget.delete('1.0', tk.END)
            output_widget.insert('1.0', ciphertext)
            
            self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'symmetric')
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def symmetric_decrypt(self, algorithm, mode, text, key_b64, iv_b64, output_widget):
        try:
            if not text.strip():
                messagebox.showerror("Error", "Please enter text to decrypt")
                return
            
            key = base64.b64decode(key_b64) if key_b64 else None
            iv = base64.b64decode(iv_b64) if iv_b64 else None
            
            if not key:
                messagebox.showerror("Error", "Please enter the key")
                return
            
            plaintext = SymmetricCrypto.decrypt_text(algorithm, mode, text.strip(), key, iv)
            output_widget.delete('1.0', tk.END)
            output_widget.insert('1.0', plaintext)
            
            self.security_monitor.log_event('successful_decrypt')
            
        except Exception as e:
            self.security_monitor.log_event('failed_decrypt', {'error': str(e)})
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def create_asymmetric_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🔑 Asymmetric Encryption")
        
        # Create a main container frame with two columns
        main_container = ttk.Frame(frame)
        main_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left frame for key generation and encryption/decryption
        left_frame = ttk.Frame(main_container)
        left_frame.pack(side='left', fill='both', expand=True, padx=5)
        
        # Right frame for digital signatures (moved to right side)
        right_frame = ttk.Frame(main_container)
        right_frame.pack(side='right', fill='both', expand=True, padx=5)
        
        # Key generation section
        key_frame = ttk.LabelFrame(left_frame, text="Key Generation", padding=10)
        key_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(key_frame, text="Key Type:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        key_type = tk.StringVar(value="RSA")
        key_type_combo = ttk.Combobox(key_frame, textvariable=key_type, 
                                      values=["RSA", "ECC"])
        key_type_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(key_frame, text="Key Size:").grid(row=0, column=2, padx=5, pady=5, sticky='w')
        key_size = tk.StringVar(value="2048")
        key_size_combo = ttk.Combobox(key_frame, textvariable=key_size, 
                                      values=["1024", "2048", "4096"])
        key_size_combo.grid(row=0, column=3, padx=5, pady=5)
        
        key_button_frame = ttk.Frame(key_frame)
        key_button_frame.grid(row=0, column=4, padx=5, pady=5, sticky='e')
        
        generate_btn = ttk.Button(key_button_frame, text="Generate Key Pair", style='Modern.TButton',
                                 command=lambda: self.generate_keypair(key_type.get(), key_size.get()))
        generate_btn.pack(side='left', padx=2)
        
        # Add Clear button
        clear_btn = ttk.Button(key_button_frame, text="Clear Keys", style='Warning.TButton',
                              command=self.clear_asymmetric_keys)
        clear_btn.pack(side='left', padx=2)
        
        # Key display
        ttk.Label(key_frame, text="Public Key (PEM):").grid(row=1, column=0, padx=5, pady=5, sticky='nw')
        self.public_key_text = scrolledtext.ScrolledText(key_frame, width=70, height=6)
        self.public_key_text.grid(row=1, column=1, columnspan=4, padx=5, pady=5)
        
        ttk.Label(key_frame, text="Private Key (PEM):").grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        self.private_key_text = scrolledtext.ScrolledText(key_frame, width=70, height=6)
        self.private_key_text.grid(row=2, column=1, columnspan=4, padx=5, pady=5)
        
        # Encryption section
        encrypt_frame = ttk.LabelFrame(left_frame, text="Encryption/Decryption", padding=15)
        encrypt_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Label(encrypt_frame, text="Message:").grid(row=0, column=0, padx=5, pady=5, sticky='nw')
        self.asym_input = scrolledtext.ScrolledText(encrypt_frame, width=70, height=7)
        self.asym_input.grid(row=0, column=1, padx=5, pady=5)
        
        button_frame = ttk.Frame(encrypt_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        encrypt_btn = ttk.Button(button_frame, text="🔒 Encrypt", style='Modern.TButton',
                                command=self.encrypt_asymmetric)
        encrypt_btn.pack(side='left', padx=5)
        
        decrypt_btn = ttk.Button(button_frame, text="🔓 Decrypt", style='Modern.TButton',
                                command=self.decrypt_asymmetric)
        decrypt_btn.pack(side='left', padx=5)
        
        clear_btn = ttk.Button(button_frame, text="Clear", style='Warning.TButton',
                              command=self.clear_asymmetric_io)
        clear_btn.pack(side='left', padx=5)
        
        ttk.Label(encrypt_frame, text="Result:").grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        self.asym_output = scrolledtext.ScrolledText(encrypt_frame, width=70, height=7)
        self.asym_output.grid(row=2, column=1, padx=5, pady=5)
        
        # Digital signatures section (moved to right side)
        sign_frame = ttk.LabelFrame(right_frame, text="Digital Signatures", padding=10)
        sign_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        ttk.Label(sign_frame, text="Message to Sign:").pack(anchor='w', pady=5)
        self.sign_input = scrolledtext.ScrolledText(sign_frame, width=60, height=6)
        self.sign_input.pack(fill='both', expand=True, padx=5, pady=5)
        
        button_frame = ttk.Frame(sign_frame)
        button_frame.pack(fill='x', pady=5)
        
        sign_btn = ttk.Button(button_frame, text="✍️ Sign", style='Modern.TButton',
                             command=self.sign_message)
        sign_btn.pack(side='left', padx=5)
        
        verify_btn = ttk.Button(button_frame, text="✓ Verify", style='Modern.TButton',
                               command=self.verify_signature)
        verify_btn.pack(side='left', padx=5)
        
        clear_btn = ttk.Button(button_frame, text="Clear", style='Warning.TButton',
                              command=self.clear_signature_fields)
        clear_btn.pack(side='left', padx=5)
        
        ttk.Label(sign_frame, text="Signature (Base64):").pack(anchor='w', pady=5)
        self.signature_text = scrolledtext.ScrolledText(sign_frame, width=60, height=4)
        self.signature_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Status label for signature verification
        self.sign_status_label = ttk.Label(sign_frame, text="", font=('Arial', 10))
        self.sign_status_label.pack(pady=5)
    
    def clear_asymmetric_keys(self):
        self.public_key_text.delete('1.0', tk.END)
        self.private_key_text.delete('1.0', tk.END)
    
    def clear_asymmetric_io(self):
        self.asym_input.delete('1.0', tk.END)
        self.asym_output.delete('1.0', tk.END)
    
    def clear_signature_fields(self):
        self.sign_input.delete('1.0', tk.END)
        self.signature_text.delete('1.0', tk.END)
        self.sign_status_label.config(text="")
    
    def generate_keypair(self, key_type, key_size):
        try:
            if key_type == "RSA":
                private_key, public_key = AsymmetricCrypto.generate_rsa_keypair(int(key_size))
                key_size_str = key_size
                
                priv_pem = AsymmetricCrypto.key_to_pem(private_key=private_key)
                pub_pem = AsymmetricCrypto.key_to_pem(public_key=public_key)
                
                self.public_key_text.delete('1.0', tk.END)
                self.public_key_text.insert('1.0', pub_pem)
                self.private_key_text.delete('1.0', tk.END)
                self.private_key_text.insert('1.0', priv_pem)
                
                messagebox.showinfo("Success", f"RSA-{key_size_str} keypair generated!")
                
            else:  # ECC
                # For ECC, we only generate the keypair for signing/verification
                # ECC doesn't support encryption directly, only ECIES (which we handle separately)
                private_key, public_key = AsymmetricCrypto.generate_ecc_keypair()
                
                priv_pem = AsymmetricCrypto.ecc_key_to_pem(private_key=private_key)
                pub_pem = AsymmetricCrypto.ecc_key_to_pem(public_key=public_key)
                
                self.public_key_text.delete('1.0', tk.END)
                self.public_key_text.insert('1.0', pub_pem)
                self.private_key_text.delete('1.0', tk.END)
                self.private_key_text.insert('1.0', priv_pem)
                
                messagebox.showinfo("Success", "ECC (SECP256R1) keypair generated for signing!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def encrypt_asymmetric(self):
        try:
            public_key_pem = self.public_key_text.get('1.0', tk.END).strip()
            message = self.asym_input.get('1.0', tk.END).strip()
            
            if not public_key_pem:
                messagebox.showerror("Error", "Please generate or enter a public key")
                return
            
            if not message:
                messagebox.showerror("Error", "Please enter a message to encrypt")
                return
            
            # Load the public key
            public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
            
            # Check the type of the public key
            if isinstance(public_key, rsa.RSAPublicKey):
                # RSA encryption
                ciphertext = AsymmetricCrypto.encrypt_rsa(public_key, message)
                
                self.asym_output.delete('1.0', tk.END)
                self.asym_output.insert('1.0', ciphertext)
                
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                # ECC encryption using ECIES
                ciphertext = AsymmetricCrypto.encrypt_ecc(public_key, message)
                
                self.asym_output.delete('1.0', tk.END)
                self.asym_output.insert('1.0', ciphertext)
            else:
                messagebox.showerror("Error", "Unsupported key type for encryption")
                return
            
            self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'asymmetric')
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_asymmetric(self):
        try:
            private_key_pem = self.private_key_text.get('1.0', tk.END).strip()
            ciphertext = self.asym_output.get('1.0', tk.END).strip()
            
            if not private_key_pem:
                messagebox.showerror("Error", "Please generate or enter a private key")
                return
            
            if not ciphertext:
                messagebox.showerror("Error", "Please encrypt a message first")
                return
            
            # Load the private key
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
            
            # Check the type of the private key
            if isinstance(private_key, rsa.RSAPrivateKey):
                # RSA decryption
                plaintext = AsymmetricCrypto.decrypt_rsa(private_key, ciphertext)
                
                self.asym_output.delete('1.0', tk.END)
                self.asym_output.insert('1.0', plaintext)
                
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                # ECC decryption using ECIES
                plaintext = AsymmetricCrypto.decrypt_ecc(private_key, ciphertext)
                
                self.asym_output.delete('1.0', tk.END)
                self.asym_output.insert('1.0', plaintext)
            else:
                messagebox.showerror("Error", "Unsupported key type for decryption")
                return
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def sign_message(self):
        try:
            private_key_pem = self.private_key_text.get('1.0', tk.END).strip()
            message = self.sign_input.get('1.0', tk.END).strip()
            
            if not private_key_pem:
                messagebox.showerror("Error", "Please generate or enter a private key")
                return
            
            if not message:
                messagebox.showerror("Error", "Please enter a message to sign")
                return
            
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
            
            # Check key type and use appropriate signing method
            if isinstance(private_key, rsa.RSAPrivateKey):
                signature = AsymmetricCrypto.sign_rsa(private_key, message)
            elif isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = AsymmetricCrypto.sign_ecc(private_key, message)
            else:
                messagebox.showerror("Error", "Unsupported key type for signing")
                return
            
            self.signature_text.delete('1.0', tk.END)
            self.signature_text.insert('1.0', signature)
            
            self.sign_status_label.config(text="✓ Message signed successfully!", foreground='green')
            
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {str(e)}")
            self.sign_status_label.config(text="✗ Signing failed", foreground='red')
    
    def verify_signature(self):
        try:
            public_key_pem = self.public_key_text.get('1.0', tk.END).strip()
            message = self.sign_input.get('1.0', tk.END).strip()
            signature = self.signature_text.get('1.0', tk.END).strip()
            
            if not public_key_pem:
                messagebox.showerror("Error", "Please generate or enter a public key")
                return
            
            if not message:
                messagebox.showerror("Error", "Please enter a message to verify")
                return
            
            if not signature:
                messagebox.showerror("Error", "Please generate a signature first")
                return
            
            public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
            
            # Check key type and use appropriate verification method
            if isinstance(public_key, rsa.RSAPublicKey):
                is_valid = AsymmetricCrypto.verify_rsa(public_key, message, signature)
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                is_valid = AsymmetricCrypto.verify_ecc(public_key, message, signature)
            else:
                messagebox.showerror("Error", "Unsupported key type for verification")
                return
            
            if is_valid:
                self.sign_status_label.config(text="✓ Signature is VALID!", foreground='green')
            else:
                self.sign_status_label.config(text="✗ Signature is INVALID!", foreground='red')
            
        except Exception as e:
            messagebox.showerror("Error", f"Verification failed: {str(e)}")
            self.sign_status_label.config(text="✗ Verification failed", foreground='red')
    
    def create_hashing_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🔢 Hashing & HMAC")
        
        # Hashing section
        hash_frame = ttk.LabelFrame(frame, text="Hashing", padding=10)
        hash_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(hash_frame, text="Algorithm:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        hash_algo = tk.StringVar(value="SHA-256")
        hash_combo = ttk.Combobox(hash_frame, textvariable=hash_algo,
                                 values=["SHA-256", "SHA-512", "SHA3-256"])
        hash_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(hash_frame, text="Input Text:").grid(row=1, column=0, padx=5, pady=5, sticky='nw')
        self.hash_input = scrolledtext.ScrolledText(hash_frame, width=70, height=6)
        self.hash_input.grid(row=1, column=1, padx=5, pady=5)
        
        hash_button_frame = ttk.Frame(hash_frame)
        hash_button_frame.grid(row=2, column=1, padx=5, pady=5, sticky='e')
        
        compute_hash_btn = ttk.Button(hash_button_frame, text="Compute Hash", style='Modern.TButton',
                                     command=lambda: self.compute_hash(hash_algo.get()))
        compute_hash_btn.pack(side='left', padx=5)
        
        clear_hash_btn = ttk.Button(hash_button_frame, text="Clear", style='Warning.TButton',
                                   command=self.clear_hash_fields)
        clear_hash_btn.pack(side='left', padx=5)
        
        ttk.Label(hash_frame, text="Hash Output:").grid(row=3, column=0, padx=5, pady=5, sticky='nw')
        self.hash_output = scrolledtext.ScrolledText(hash_frame, width=70, height=6)
        self.hash_output.grid(row=3, column=1, padx=5, pady=5)
        
        # HMAC section
        hmac_frame = ttk.LabelFrame(frame, text="HMAC", padding=10)
        hmac_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(hmac_frame, text="Algorithm:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        hmac_algo = tk.StringVar(value="HMAC-SHA256")
        hmac_combo = ttk.Combobox(hmac_frame, textvariable=hmac_algo,
                                 values=["HMAC-SHA256", "HMAC-SHA512"])
        hmac_combo.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(hmac_frame, text="Key:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.hmac_key_entry = ttk.Entry(hmac_frame, width=70)
        self.hmac_key_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(hmac_frame, text="Input Text:").grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        self.hmac_input = scrolledtext.ScrolledText(hmac_frame, width=70, height=6)
        self.hmac_input.grid(row=2, column=1, padx=5, pady=5)
        
        hmac_button_frame = ttk.Frame(hmac_frame)
        hmac_button_frame.grid(row=3, column=1, padx=5, pady=5, sticky='e')
        
        compute_hmac_btn = ttk.Button(hmac_button_frame, text="Compute HMAC", style='Modern.TButton',
                                     command=lambda: self.compute_hmac(hmac_algo.get()))
        compute_hmac_btn.pack(side='left', padx=5)
        
        clear_hmac_btn = ttk.Button(hmac_button_frame, text="Clear", style='Warning.TButton',
                                   command=self.clear_hmac_fields)
        clear_hmac_btn.pack(side='left', padx=5)
        
        ttk.Label(hmac_frame, text="HMAC Output:").grid(row=4, column=0, padx=5, pady=5, sticky='nw')
        self.hmac_output = scrolledtext.ScrolledText(hmac_frame, width=70, height=6)
        self.hmac_output.grid(row=4, column=1, padx=5, pady=5)
    
    def clear_hash_fields(self):
        self.hash_input.delete('1.0', tk.END)
        self.hash_output.delete('1.0', tk.END)
    
    def clear_hmac_fields(self):
        self.hmac_key_entry.delete(0, tk.END)
        self.hmac_input.delete('1.0', tk.END)
        self.hmac_output.delete('1.0', tk.END)
    
    def compute_hash(self, algorithm):
        try:
            text = self.hash_input.get('1.0', tk.END).strip()
            if not text:
                messagebox.showerror("Error", "Please enter text to hash")
                return
            
            hash_value = HashUtils.compute_hash(algorithm, text)
            self.hash_output.delete('1.0', tk.END)
            self.hash_output.insert('1.0', hash_value)
            
            self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'hashing')
            
        except Exception as e:
            messagebox.showerror("Error", f"Hash computation failed: {str(e)}")
    
    def compute_hmac(self, algorithm):
        try:
            text = self.hmac_input.get('1.0', tk.END).strip()
            key = self.hmac_key_entry.get()
            
            if not text:
                messagebox.showerror("Error", "Please enter text to compute HMAC")
                return
            
            if not key:
                messagebox.showerror("Error", "Please enter a key for HMAC")
                return
            
            hmac_value = HashUtils.compute_hmac(algorithm, text, key)
            self.hmac_output.delete('1.0', tk.END)
            self.hmac_output.insert('1.0', hmac_value)
            
            self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'hashing')
            
        except Exception as e:
            messagebox.showerror("Error", f"HMAC computation failed: {str(e)}")
    
    def create_hybrid_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🔗 Hybrid Encryption")
        
        # Create a main frame with left and right sections
        main_frame = ttk.Frame(frame)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Left frame for encryption
        left_frame = ttk.LabelFrame(main_frame, text="Encryption Section", padding=10)
        left_frame.pack(side='left', fill='both', expand=True, padx=5, pady=5)
        
        # Key generation
        key_frame = ttk.LabelFrame(left_frame, text="Generate Keys", padding=10)
        key_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(key_frame, text="Symmetric Algorithm:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        sym_algo = tk.StringVar(value="AES")
        sym_combo = ttk.Combobox(key_frame, textvariable=sym_algo, 
                                 values=["AES", "ChaCha20"])
        sym_combo.grid(row=0, column=1, padx=5, pady=5)
        
        key_button_frame = ttk.Frame(key_frame)
        key_button_frame.grid(row=0, column=2, padx=5, pady=5)
        
        generate_btn = ttk.Button(key_button_frame, text="Generate RSA Key Pair", style='Modern.TButton',
                                 command=lambda: self.generate_hybrid_keys())
        generate_btn.pack(side='left', padx=2)
        
        # Add Clear button
        clear_btn = ttk.Button(key_button_frame, text="Clear Keys", style='Warning.TButton',
                              command=self.clear_hybrid_keys)
        clear_btn.pack(side='left', padx=2)
        
        ttk.Label(key_frame, text="Public Key:").grid(row=1, column=0, padx=5, pady=5, sticky='nw')
        self.hybrid_pub_key = scrolledtext.ScrolledText(key_frame, width=60, height=5)
        self.hybrid_pub_key.grid(row=1, column=1, columnspan=2, padx=5, pady=5)
        
        ttk.Label(key_frame, text="Private Key:").grid(row=2, column=0, padx=5, pady=5, sticky='nw')
        self.hybrid_priv_key = scrolledtext.ScrolledText(key_frame, width=60, height=5)
        self.hybrid_priv_key.grid(row=2, column=1, columnspan=2, padx=5, pady=5)
        
        # Encryption section
        encrypt_frame = ttk.LabelFrame(left_frame, text="Encrypt", padding=10)
        encrypt_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        ttk.Label(encrypt_frame, text="Message:").pack(anchor='w', pady=5)
        self.hybrid_input = scrolledtext.ScrolledText(encrypt_frame, height=6)
        self.hybrid_input.pack(fill='both', expand=True, padx=5, pady=5)
        
        encrypt_button_frame = ttk.Frame(encrypt_frame)
        encrypt_button_frame.pack(pady=5)
        
        encrypt_btn = ttk.Button(encrypt_button_frame, text="🔒 Hybrid Encrypt", style='Modern.TButton',
                                command=lambda: self.hybrid_encrypt(sym_algo.get()))
        encrypt_btn.pack(side='left', padx=5)
        
        clear_input_btn = ttk.Button(encrypt_button_frame, text="Clear Input", style='Warning.TButton',
                                    command=self.clear_hybrid_input)
        clear_input_btn.pack(side='left', padx=5)
        
        # Right frame for decryption and results
        right_frame = ttk.LabelFrame(main_frame, text="Decryption Section", padding=10)
        right_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        # Encrypted result display
        result_frame = ttk.LabelFrame(right_frame, text="Encrypted Result", padding=10)
        result_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.hybrid_result = scrolledtext.ScrolledText(result_frame, height=8)
        self.hybrid_result.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Decryption section
        decrypt_frame = ttk.LabelFrame(right_frame, text="Decrypt", padding=10)
        decrypt_frame.pack(fill='x', padx=10, pady=5)
        
        decrypt_button_frame = ttk.Frame(decrypt_frame)
        decrypt_button_frame.pack(pady=5)
        
        decrypt_btn = ttk.Button(decrypt_button_frame, text="🔓 Hybrid Decrypt", style='Modern.TButton',
                                command=self.hybrid_decrypt)
        decrypt_btn.pack(side='left', padx=5)
        
        clear_result_btn = ttk.Button(decrypt_button_frame, text="Clear Result", style='Warning.TButton',
                                     command=self.clear_hybrid_result)
        clear_result_btn.pack(side='left', padx=5)
        
        # Decrypted message display
        decrypted_frame = ttk.LabelFrame(right_frame, text="Decrypted Message", padding=10)
        decrypted_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Add scrollbar for decrypted message
        decrypted_container = ttk.Frame(decrypted_frame)
        decrypted_container.pack(fill='both', expand=True)
        
        # Create a scrollbar
        decrypted_scrollbar = ttk.Scrollbar(decrypted_container)
        decrypted_scrollbar.pack(side='right', fill='y')
        
        # Create text widget with scrollbar
        self.hybrid_decrypted = tk.Text(decrypted_container, wrap=tk.WORD, yscrollcommand=decrypted_scrollbar.set,
                                       height=10, width=40)
        self.hybrid_decrypted.pack(side='left', fill='both', expand=True)
        
        # Configure scrollbar
        decrypted_scrollbar.config(command=self.hybrid_decrypted.yview)
        
        # Add Clear button for decrypted message
        clear_decrypted_btn = ttk.Button(decrypted_frame, text="Clear Decrypted", style='Warning.TButton',
                                        command=self.clear_hybrid_decrypted)
        clear_decrypted_btn.pack(pady=5)
    
    def clear_hybrid_keys(self):
        self.hybrid_pub_key.delete('1.0', tk.END)
        self.hybrid_priv_key.delete('1.0', tk.END)
    
    def clear_hybrid_input(self):
        self.hybrid_input.delete('1.0', tk.END)
    
    def clear_hybrid_result(self):
        self.hybrid_result.delete('1.0', tk.END)
    
    def clear_hybrid_decrypted(self):
        self.hybrid_decrypted.delete('1.0', tk.END)
    
    def generate_hybrid_keys(self):
        try:
            private_key, public_key = AsymmetricCrypto.generate_rsa_keypair(2048)
            
            priv_pem = AsymmetricCrypto.key_to_pem(private_key=private_key)
            pub_pem = AsymmetricCrypto.key_to_pem(public_key=public_key)
            
            self.hybrid_pub_key.delete('1.0', tk.END)
            self.hybrid_pub_key.insert('1.0', pub_pem)
            self.hybrid_priv_key.delete('1.0', tk.END)
            self.hybrid_priv_key.insert('1.0', priv_pem)
            
            messagebox.showinfo("Success", "RSA keypair generated for hybrid encryption!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def hybrid_encrypt(self, sym_algo):
        try:
            public_key_pem = self.hybrid_pub_key.get('1.0', tk.END).strip()
            message = self.hybrid_input.get('1.0', tk.END).strip()
            
            if not public_key_pem:
                messagebox.showerror("Error", "Please generate RSA keys first")
                return
            
            if not message:
                messagebox.showerror("Error", "Please enter a message to encrypt")
                return
            
            public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
            
            # Perform hybrid encryption
            hybrid_data = HybridCrypto.encrypt(sym_algo, "RSA", message, public_key)
            
            # Display result in JSON format for easier parsing
            import json
            result_json = json.dumps(hybrid_data, indent=2)
            
            self.hybrid_result.delete('1.0', tk.END)
            self.hybrid_result.insert('1.0', result_json)
            
            messagebox.showinfo("Success", "Hybrid encryption completed!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Hybrid encryption failed: {str(e)}")
    
    def hybrid_decrypt(self):
        try:
            private_key_pem = self.hybrid_priv_key.get('1.0', tk.END).strip()
            result_text = self.hybrid_result.get('1.0', tk.END).strip()
            
            if not private_key_pem:
                messagebox.showerror("Error", "Please generate RSA keys first")
                return
            
            if not result_text.strip():
                messagebox.showerror("Error", "No encrypted data to decrypt")
                return
            
            # Try to parse as JSON
            import json
            try:
                hybrid_data = json.loads(result_text)
            except json.JSONDecodeError:
                # If not JSON, try to parse the old format
                lines = result_text.strip().split('\n')
                hybrid_data = {}
                current_section = None
                
                for line in lines:
                    if 'Encrypted Key:' in line:
                        current_section = 'encrypted_key'
                        hybrid_data['encrypted_key'] = ''
                    elif 'IV:' in line:
                        current_section = 'iv'
                        hybrid_data['iv'] = ''
                    elif 'Ciphertext:' in line:
                        current_section = 'ciphertext'
                        hybrid_data['ciphertext'] = ''
                    elif 'Algorithm:' in line:
                        parts = line.split(':')
                        if len(parts) > 1:
                            hybrid_data['algorithm'] = parts[1].strip()
                    elif current_section and line.strip():
                        hybrid_data[current_section] += line.strip()
            
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None, backend=default_backend())
            
            # Try to decrypt
            plaintext = HybridCrypto.decrypt(hybrid_data, private_key)
            
            # Clear and display decrypted message in the scrollable text box
            self.hybrid_decrypted.delete('1.0', tk.END)
            self.hybrid_decrypted.insert('1.0', plaintext)
            
            # Show success message
            messagebox.showinfo("Success", "Hybrid decryption completed!\n\nThe decrypted message is displayed in the 'Decrypted Message' section below.")
            
        except Exception as e:
            self.security_monitor.log_event('failed_decrypt', {'error': str(e)})
            messagebox.showerror("Error", f"Hybrid decryption failed: {str(e)}")
    
    def create_file_encryption_tab(self, notebook):
        """Create file encryption/decryption tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="📁 File Encryption")
        
        # Create notebook for different file operations
        file_notebook = ttk.Notebook(frame)
        file_notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Tab 1: Symmetric File Encryption
        self.create_symmetric_file_tab(file_notebook)
        
        # Tab 2: Hybrid File Encryption
        self.create_hybrid_file_tab(file_notebook)
        
        # Tab 3: File Sharing
        self.create_file_sharing_tab(file_notebook)
    
    def create_symmetric_file_tab(self, notebook):
        """Symmetric file encryption tab"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🔐 Symmetric File")
        
        # File selection
        file_frame = ttk.LabelFrame(frame, text="File Selection", padding=10)
        file_frame.pack(fill='x', padx=10, pady=5)
        
        self.file_path_var = tk.StringVar()
        ttk.Label(file_frame, text="Selected File:").pack(side='left', padx=5)
        ttk.Entry(file_frame, textvariable=self.file_path_var, width=50).pack(side='left', padx=5)
        ttk.Button(file_frame, text="Browse", 
                  command=lambda: self.browse_file(self.file_path_var)).pack(side='left', padx=5)
        
        # Encryption settings
        settings_frame = ttk.LabelFrame(frame, text="Encryption Settings", padding=10)
        settings_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(settings_frame, text="Algorithm:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.file_algo_var = tk.StringVar(value="AES")
        ttk.Combobox(settings_frame, textvariable=self.file_algo_var, 
                    values=["AES", "ChaCha20"]).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(settings_frame, text="Mode:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.file_mode_var = tk.StringVar(value="GCM")
        ttk.Combobox(settings_frame, textvariable=self.file_mode_var,
                    values=["CBC", "CTR", "GCM"]).grid(row=1, column=1, padx=5, pady=5)
        
        # Encryption method
        ttk.Label(settings_frame, text="Encryption Method:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.enc_method_var = tk.StringVar(value="password")
        ttk.Radiobutton(settings_frame, text="Password", variable=self.enc_method_var, 
                       value="password").grid(row=2, column=1, padx=5, pady=5, sticky='w')
        ttk.Radiobutton(settings_frame, text="Key/IV", variable=self.enc_method_var,
                       value="key").grid(row=2, column=2, padx=5, pady=5, sticky='w')
        
        # Password/Key fields
        self.password_frame = ttk.Frame(settings_frame)
        self.password_frame.grid(row=3, column=0, columnspan=3, pady=5, sticky='w')
        
        ttk.Label(self.password_frame, text="Password:").grid(row=0, column=0, padx=5, pady=2)
        self.file_password = ttk.Entry(self.password_frame, show="*", width=30)
        self.file_password.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(self.password_frame, text="Confirm:").grid(row=1, column=0, padx=5, pady=2)
        self.file_password_confirm = ttk.Entry(self.password_frame, show="*", width=30)
        self.file_password_confirm.grid(row=1, column=1, padx=5, pady=2)
        
        self.key_frame = ttk.Frame(settings_frame)
        self.key_frame.grid(row=3, column=0, columnspan=3, pady=5, sticky='w')
        
        ttk.Label(self.key_frame, text="Key (Base64):").grid(row=0, column=0, padx=5, pady=2)
        self.file_key_entry = ttk.Entry(self.key_frame, width=50)
        self.file_key_entry.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(self.key_frame, text="IV (Base64):").grid(row=1, column=0, padx=5, pady=2)
        self.file_iv_entry = ttk.Entry(self.key_frame, width=50)
        self.file_iv_entry.grid(row=1, column=1, padx=5, pady=2)
        
        key_button_frame = ttk.Frame(self.key_frame)
        key_button_frame.grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Button(key_button_frame, text="Generate Key/IV",
                  command=self.generate_file_key_iv).pack(side='left', padx=2)
        
        # Add Clear button
        ttk.Button(key_button_frame, text="Clear Keys", style='Warning.TButton',
                  command=self.clear_file_keys).pack(side='left', padx=2)
        
        # Show appropriate frame based on method
        self.enc_method_var.trace('w', self.toggle_encryption_method)
        self.toggle_encryption_method()
        
        # Action buttons
        action_frame = ttk.Frame(frame)
        action_frame.pack(pady=10)
        
        ttk.Button(action_frame, text="🔒 Encrypt File", style='Modern.TButton',
                  command=self.encrypt_selected_file).pack(side='left', padx=5)
        ttk.Button(action_frame, text="💾 Save Encrypted File", style='Success.TButton',
                  command=self.save_encrypted_file).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🔓 Decrypt File", style='Modern.TButton',
                  command=self.decrypt_selected_file).pack(side='left', padx=5)
        
        # Clear button
        ttk.Button(action_frame, text="🧹 Clear All", style='Warning.TButton',
                  command=self.clear_file_encryption_all).pack(side='left', padx=5)
        
        # Status area
        status_frame = ttk.LabelFrame(frame, text="Status & Information", padding=10)
        status_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.file_status_text = scrolledtext.ScrolledText(status_frame, height=10)
        self.file_status_text.pack(fill='both', expand=True)
        
        # Clear status button
        ttk.Button(status_frame, text="Clear Status", style='Warning.TButton',
                  command=lambda: self.file_status_text.delete('1.0', tk.END)).pack(pady=5)
        
        # Share button
        share_frame = ttk.Frame(frame)
        share_frame.pack(pady=5)
        
        ttk.Button(share_frame, text="📤 Share This File", style='Admin.TButton',
                  command=self.share_current_file).pack(side='left', padx=5)
    
    def clear_file_keys(self):
        self.file_key_entry.delete(0, tk.END)
        self.file_iv_entry.delete(0, tk.END)
        self.file_password.delete(0, tk.END)
        self.file_password_confirm.delete(0, tk.END)
    
    def clear_file_encryption_all(self):
        self.file_path_var.set("")
        self.clear_file_keys()
        self.file_status_text.delete('1.0', tk.END)
    
    def create_hybrid_file_tab(self, notebook):
        """Hybrid file encryption tab - FIXED VERSION"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="🔗 Hybrid File")
        
        # File selection
        file_frame = ttk.LabelFrame(frame, text="File Selection", padding=10)
        file_frame.pack(fill='x', padx=10, pady=5)
        
        self.hybrid_file_path_var = tk.StringVar()
        ttk.Label(file_frame, text="Selected File:").pack(side='left', padx=5)
        ttk.Entry(file_frame, textvariable=self.hybrid_file_path_var, width=50).pack(side='left', padx=5)
        ttk.Button(file_frame, text="Browse", 
                  command=lambda: self.browse_file(self.hybrid_file_path_var)).pack(side='left', padx=5)
        
        # Clear file button
        ttk.Button(file_frame, text="Clear", style='Warning.TButton',
                  command=lambda: self.hybrid_file_path_var.set("")).pack(side='left', padx=5)
        
        # Key management
        key_frame = ttk.LabelFrame(frame, text="Key Management", padding=10)
        key_frame.pack(fill='x', padx=10, pady=5)
        
        # FIXED: Use correct method name
        ttk.Button(key_frame, text="Generate RSA Key Pair", style='Modern.TButton',
                 command=self.generate_hybrid_file_keys).pack(pady=(2, 2))
        
        ttk.Label(key_frame, text="Public Key (PEM):").pack(anchor='w', pady=2)
        self.hybrid_pub_key_text = scrolledtext.ScrolledText(key_frame, height=4)
        self.hybrid_pub_key_text.pack(fill='x', pady=5)
        
        ttk.Label(key_frame, text="Private Key (PEM):").pack(anchor='w', pady=2)
        self.hybrid_priv_key_text = scrolledtext.ScrolledText(key_frame, height=4)
        self.hybrid_priv_key_text.pack(fill='x', pady=5)
        
        # Add Clear button for keys
        clear_key_button = ttk.Button(key_frame, text="Clear Keys", style='Warning.TButton',
                                     command=self.clear_hybrid_file_keys)
        clear_key_button.pack(pady=5)
        
        # Action buttons
        action_frame = ttk.Frame(frame)
        action_frame.pack(pady=10)
        
        ttk.Button(action_frame, text="🔒 Hybrid Encrypt File", style='Modern.TButton',
                  command=self.hybrid_encrypt_file).pack(side='left', padx=5)
        ttk.Button(action_frame, text="💾 Save Hybrid Encrypted File", style='Success.TButton',
                  command=self.save_hybrid_encrypted_file).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🔓 Hybrid Decrypt", style='Modern.TButton',
                  command=self.hybrid_decrypt_file).pack(side='left', padx=5)
        
        # Clear all button
        ttk.Button(action_frame, text="Clear All", style='Warning.TButton',
                  command=self.clear_hybrid_file_all).pack(side='left', padx=5)
        
        # Status area
        status_frame = ttk.LabelFrame(frame, text="Status & Information", padding=2)
        status_frame.pack(fill='both', expand=True, padx=2, pady=2)
        
        self.hybrid_status_text = scrolledtext.ScrolledText(status_frame, height=3)
        self.hybrid_status_text.pack(fill='both', expand=True)
        
        # Clear status button
        ttk.Button(status_frame, text="Clear Status", style='Warning.TButton',
                  command=lambda: self.hybrid_status_text.delete('1.0', tk.END)).pack(pady=5)
        
        # Share button
        share_frame = ttk.Frame(frame)
        share_frame.pack(pady=5)
        
        ttk.Button(share_frame, text="📤 Share This File", style='Admin.TButton',
                  command=self.share_hybrid_file).pack(side='left', padx=5)
    
    def generate_hybrid_file_keys(self):
        """Generate RSA key pair for hybrid file encryption - FIXED METHOD"""
        try:
            private_key, public_key = AsymmetricCrypto.generate_rsa_keypair(2048)
            
            priv_pem = AsymmetricCrypto.key_to_pem(private_key=private_key)
            pub_pem = AsymmetricCrypto.key_to_pem(public_key=public_key)
            
            self.hybrid_pub_key_text.delete('1.0', tk.END)
            self.hybrid_pub_key_text.insert('1.0', pub_pem)
            self.hybrid_priv_key_text.delete('1.0', tk.END)
            self.hybrid_priv_key_text.insert('1.0', priv_pem)
            
            self.hybrid_status_text.delete('1.0', tk.END)
            self.hybrid_status_text.insert('1.0', "✓ RSA keypair generated successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def clear_hybrid_file_keys(self):
        self.hybrid_pub_key_text.delete('1.0', tk.END)
        self.hybrid_priv_key_text.delete('1.0', tk.END)
    
    def clear_hybrid_file_all(self):
        self.hybrid_file_path_var.set("")
        self.clear_hybrid_file_keys()
        self.hybrid_status_text.delete('1.0', tk.END)
    
    def create_file_sharing_tab(self, notebook):
        """File sharing tab with enhanced preview features and one-time download"""
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="📤 File Sharing")
        
        # Notebook for share/receive
        share_notebook = ttk.Notebook(frame)
        share_notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Share file tab - UPDATED WITH SCROLLBARS
        share_frame = ttk.Frame(share_notebook)
        share_notebook.add(share_frame, text="Share File")
        
        # Create a canvas and scrollbars for the share_frame
        share_canvas = tk.Canvas(share_frame)
        v_scrollbar = ttk.Scrollbar(share_frame, orient="vertical", command=share_canvas.yview)
        h_scrollbar = ttk.Scrollbar(share_frame, orient="horizontal", command=share_canvas.xview)
        
        # Configure the canvas
        share_canvas.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        share_canvas.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Create a frame inside the canvas
        scrollable_share_frame = ttk.Frame(share_canvas)
        share_canvas.create_window((0, 0), window=scrollable_share_frame, anchor="nw")
        
        # Configure the scrollable frame to resize with content
        scrollable_share_frame.bind(
            "<Configure>",
            lambda e: share_canvas.configure(scrollregion=share_canvas.bbox("all"))
        )
        
        # File to share
        share_file_frame = ttk.LabelFrame(scrollable_share_frame, text="File to Share", padding=10)
        share_file_frame.pack(fill='x', pady=5, padx=10)
        
        self.share_file_path_var = tk.StringVar()
        ttk.Label(share_file_frame, text="File:").pack(side='left', padx=5)
        ttk.Entry(share_file_frame, textvariable=self.share_file_path_var, width=30).pack(side='left', padx=5)
        ttk.Button(share_file_frame, text="Browse", 
                  command=lambda: self.browse_file(self.share_file_path_var)).pack(side='left', padx=5)
        
        # Clear file button
        ttk.Button(share_file_frame, text="Clear", style='Warning.TButton',
                  command=lambda: self.share_file_path_var.set("")).pack(side='left', padx=5)
        
        # Preview original content (for text files)
        ttk.Button(share_file_frame, text="👁️ Preview Original",
                  command=self.preview_original_file).pack(side='left', padx=5)
        
        # Recipient selection
        recipient_frame = ttk.LabelFrame(scrollable_share_frame, text="Recipient", padding=10)
        recipient_frame.pack(fill='x', pady=5, padx=10)
        
        ttk.Label(recipient_frame, text="Recipient User:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.recipient_email = ttk.Entry(recipient_frame, width=30)
        self.recipient_email.grid(row=0, column=1, padx=5, pady=5)
        
        # Get all users for dropdown
        users = self.user_manager.get_all_users()
        current_user_email = self.user_manager.current_user['email']
        user_emails = [email for email in users.keys() if email != current_user_email]
        
        if user_emails:
            ttk.Label(recipient_frame, text="Or Select from Users:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
            self.recipient_combo = ttk.Combobox(recipient_frame, values=user_emails, width=28)
            self.recipient_combo.grid(row=1, column=1, padx=5, pady=5)
            self.recipient_combo.bind('<<ComboboxSelected>>', 
                                     lambda e: self.recipient_email.delete(0, tk.END) or 
                                               self.recipient_email.insert(0, self.recipient_combo.get()))
        
        # Clear recipient button
        ttk.Button(recipient_frame, text="Clear", style='Warning.TButton',
                  command=lambda: self.recipient_email.delete(0, tk.END)).grid(row=1, column=2, padx=5, pady=5)
        
        # Encryption method for sharing
        enc_frame = ttk.LabelFrame(scrollable_share_frame, text="Encryption Method", padding=10)
        enc_frame.pack(fill='x', pady=5, padx=10)
        
        self.share_enc_method = tk.StringVar(value="symmetric")
        
        # Symmetric encryption frame
        symmetric_frame = ttk.LabelFrame(enc_frame, text="Symmetric (Password)", padding=10)
        symmetric_frame.pack(fill='x', pady=5)
        
        ttk.Radiobutton(symmetric_frame, text="Use Symmetric Encryption", variable=self.share_enc_method,
                       value="symmetric", command=self.toggle_share_encryption_method).pack(anchor='w', pady=2)
        
        self.share_password_frame = ttk.Frame(symmetric_frame)
        self.share_password_frame.pack(fill='x', pady=5)
        
        ttk.Label(self.share_password_frame, text="Password:").grid(row=0, column=0, padx=5, pady=2)
        self.share_password = ttk.Entry(self.share_password_frame, show="*", width=25)
        self.share_password.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(self.share_password_frame, text="Confirm:").grid(row=1, column=0, padx=5, pady=2)
        self.share_password_confirm = ttk.Entry(self.share_password_frame, show="*", width=25)
        self.share_password_confirm.grid(row=1, column=1, padx=5, pady=2)
        
        # Add Clear button for symmetric
        ttk.Button(self.share_password_frame, text="Clear", style='Warning.TButton',
                  command=self.clear_share_password).grid(row=2, column=1, padx=5, pady=5, sticky='w')
        
        # Hybrid encryption frame
        hybrid_frame = ttk.LabelFrame(enc_frame, text="Hybrid (RSA + AES)", padding=10)
        hybrid_frame.pack(fill='x', pady=5)
        
        ttk.Radiobutton(hybrid_frame, text="Use Hybrid Encryption", variable=self.share_enc_method,
                       value="hybrid", command=self.toggle_share_encryption_method).pack(anchor='w', pady=1)
        
        # Generate RSA keys button
        hybrid_button_frame = ttk.Frame(hybrid_frame)
        hybrid_button_frame.pack(pady=2)
        
        ttk.Button(hybrid_button_frame, text="Generate RSA Key Pair", style='Modern.TButton',
                  command=self.generate_share_hybrid_keys).pack(side='left', padx=2)
        
        # Add Clear button for hybrid keys
        ttk.Button(hybrid_button_frame, text="Clear Keys", style='Warning.TButton',
                  command=self.clear_share_hybrid_keys).pack(side='left', padx=2)
        
        # Key display area
        self.share_hybrid_keys_frame = ttk.LabelFrame(hybrid_frame, text="RSA Keys", padding=5)
        self.share_hybrid_keys_frame.pack(fill='both', expand=True, pady=2)
        
        # Create two columns for public and private keys
        keys_grid = ttk.Frame(self.share_hybrid_keys_frame)
        keys_grid.pack(fill='both', expand=True)
        
        # Public Key Column
        pub_key_frame = ttk.LabelFrame(keys_grid, text="Public Key (PEM)", padding=5)
        pub_key_frame.pack(side='left', fill='both', expand=True, padx=5)
        
        self.share_public_key_text = scrolledtext.ScrolledText(pub_key_frame, height=8, wrap='none')
        self.share_public_key_text.pack(fill='both', expand=True)
        
        # Private Key Column
        priv_key_frame = ttk.LabelFrame(keys_grid, text="Private Key (PEM) - Copy this for decryption", padding=2)
        priv_key_frame.pack(side='right', fill='both', expand=True, padx=5)
        
        self.share_private_key_text = scrolledtext.ScrolledText(priv_key_frame, height=8, wrap='none')
        self.share_private_key_text.pack(fill='both', expand=True)
        
        # One-time download option
        one_time_frame = ttk.LabelFrame(scrollable_share_frame, text="Security Options", padding=10)
        one_time_frame.pack(fill='x', pady=5, padx=10)
        
        self.one_time_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(one_time_frame, text="🔒 One-time download link (file self-destructs after first view/download)",
                       variable=self.one_time_var).pack(anchor='w', pady=2)
        
        # Share button
        share_btn_frame = ttk.Frame(scrollable_share_frame)
        share_btn_frame.pack(pady=10, padx=10)
        
        ttk.Button(share_btn_frame, text="📤 Share File", style='Success.TButton',
                  command=self.share_file).pack(side='left', padx=5)
        
        # Clear all button
        ttk.Button(share_btn_frame, text="Clear All", style='Warning.TButton',
                  command=self.clear_share_all).pack(side='left', padx=5)
        
        # Instructions frame
        instructions_frame = ttk.LabelFrame(scrollable_share_frame, text="Instructions", padding=10)
        instructions_frame.pack(fill='x', pady=5, padx=10)
        
        instructions_text = scrolledtext.ScrolledText(instructions_frame, wrap=tk.WORD, height=15)
        instructions_text.pack(fill='both', expand=True)
        
        instructions = """
=== Symmetric Encryption ===
1. Select a file to share
2. Choose "Symmetric (Password)"
3. Enter a password (must be shared with recipient)
4. Recipient needs the password to decrypt

=== Hybrid Encryption (RSA + AES) ===
1. Select a file to share
2. Choose "Hybrid (RSA + AES)"
3. Click "Generate RSA Key Pair"
4. Public key will be used for encryption
5. PRIVATE KEY will be displayed - COPY THIS!
6. Share the private key with recipient for decryption

=== One-Time Download ===
• When enabled, file can only be downloaded once
• After first download, file becomes corrupted
• Useful for sensitive documents

=== Recipient Instructions ===
• Share the file ID with recipient
• For symmetric: Share the password
• For hybrid: Share the private key
• Recipient uses "Received Files" tab to decrypt
"""
        
        instructions_text.insert('1.0', instructions)
        instructions_text.config(state='disabled')
        
        # Status area
        status_frame = ttk.LabelFrame(scrollable_share_frame, text="Status", padding=10)
        status_frame.pack(fill='x', pady=5, padx=10)
        
        self.sharing_status_text = scrolledtext.ScrolledText(status_frame, height=8)
        self.sharing_status_text.pack(fill='both', expand=True)
        
        # Clear status button
        ttk.Button(status_frame, text="Clear Status", style='Warning.TButton',
                  command=lambda: self.sharing_status_text.delete('1.0', tk.END)).pack(pady=5)
        
        # Received files tab
        receive_frame = ttk.Frame(share_notebook)
        share_notebook.add(receive_frame, text="Received Files")
        
        # Refresh button
        refresh_frame = ttk.Frame(receive_frame)
        refresh_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(refresh_frame, text="🔄 Refresh", command=self.refresh_received_files).pack(side='left', padx=5)
        
        # Stats label
        self.share_stats_label = ttk.Label(refresh_frame, text="", font=('Arial', 9))
        self.share_stats_label.pack(side='left', padx=10)
        
        # Clear received files button
        ttk.Button(refresh_frame, text="Clear Fields", style='Warning.TButton',
                  command=self.clear_received_fields).pack(side='left', padx=5)
        
        # Received files list
        list_frame = ttk.LabelFrame(receive_frame, text="Files Shared With You", padding=3)
        list_frame.pack(fill='both', expand=True, padx=3, pady=5)
        
        # Treeview for received files
        columns = ('ID', 'Sender', 'Filename', 'Date', 'Encryption', 'One-Time')
        self.received_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=5)
        
        for col in columns:
            self.received_tree.heading(col, text=col)
            self.received_tree.column(col, width=100, minwidth=50)
        
        self.received_tree.column('ID', width=120)
        self.received_tree.column('Sender', width=150)
        self.received_tree.column('Filename', width=150)
        self.received_tree.column('Date', width=120)
        self.received_tree.column('Encryption', width=100)
        self.received_tree.column('One-Time', width=80)
        
        # Scrollbars
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.received_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.received_tree.xview)
        self.received_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.received_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Action buttons for received files
        action_frame = ttk.Frame(receive_frame)
        action_frame.pack(pady=10)
        
        ttk.Button(action_frame, text="👁️ View Details", 
                  command=self.view_received_file_details).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🔍 Preview Encrypted", 
                  command=self.preview_encrypted_file).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🔓 Decrypt & View", style='Modern.TButton',
                  command=self.decrypt_and_view_file).pack(side='left', padx=5)
        ttk.Button(action_frame, text="💾 Save Decrypted", style='Success.TButton',
                  command=self.decrypt_and_save_file).pack(side='left', padx=5)
        ttk.Button(action_frame, text="🗑️ Remove", style='Danger.TButton',
                  command=self.remove_received_file).pack(side='left', padx=5)
        
        # Decryption credentials frame
        decrypt_frame = ttk.LabelFrame(receive_frame, text="Decryption Credentials", padding=10)
        decrypt_frame.pack(fill='x', padx=10, pady=5)
        
        # Encryption type selection
        type_frame = ttk.Frame(decrypt_frame)
        type_frame.pack(fill='x', pady=5)
        
        ttk.Label(type_frame, text="Decryption Type:").pack(side='left', padx=5)
        self.decrypt_type_var = tk.StringVar(value="password")
        type_combo = ttk.Combobox(type_frame, textvariable=self.decrypt_type_var,
                                 values=["password", "key/iv", "private_key"], width=15)
        type_combo.pack(side='left', padx=5)
        type_combo.bind('<<ComboboxSelected>>', lambda e: self.toggle_decryption_fields())
        
        # Clear credentials button
        ttk.Button(type_frame, text="Clear Credentials", style='Warning.TButton',
                  command=self.clear_decryption_credentials).pack(side='left', padx=5)
        
        # Password field
        self.password_decrypt_frame = ttk.Frame(decrypt_frame)
        self.password_decrypt_frame.pack(fill='x', pady=5)
        
        ttk.Label(self.password_decrypt_frame, text="Password:").pack(side='left', padx=5)
        self.decrypt_password = ttk.Entry(self.password_decrypt_frame, show="*", width=40)
        self.decrypt_password.pack(side='left', padx=5)
        
        # Key/IV field
        self.key_iv_decrypt_frame = ttk.Frame(decrypt_frame)
        
        key_iv_grid = ttk.Frame(self.key_iv_decrypt_frame)
        key_iv_grid.pack(fill='x', pady=5)
        
        ttk.Label(key_iv_grid, text="Key (Base64):").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.decrypt_key = ttk.Entry(key_iv_grid, width=50)
        self.decrypt_key.grid(row=0, column=1, padx=5, pady=2)
        
        ttk.Label(key_iv_grid, text="IV (Base64):").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.decrypt_iv = ttk.Entry(key_iv_grid, width=50)
        self.decrypt_iv.grid(row=1, column=1, padx=5, pady=2)
        
        # Private key field
        self.private_key_decrypt_frame = ttk.Frame(decrypt_frame)
        
        ttk.Label(self.private_key_decrypt_frame, text="Private Key (PEM):").pack(anchor='w', pady=2)
        self.decrypt_private_key = scrolledtext.ScrolledText(self.private_key_decrypt_frame, height=4, width=50)
        self.decrypt_private_key.pack(fill='x', pady=5)
        
        # Initialize decryption fields
        self.toggle_decryption_fields()
        
        # Content display area (for previewing encrypted/decrypted content)
        content_frame = ttk.LabelFrame(receive_frame, text="File Content Viewer", padding=2)
        content_frame.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Notebook for different content views
        content_notebook = ttk.Notebook(content_frame)
        content_notebook.pack(fill='both', expand=True)
        
        # Encrypted content tab
        encrypted_tab = ttk.Frame(content_notebook)
        content_notebook.add(encrypted_tab, text="🔒 Encrypted View")
        
        self.encrypted_content_text = scrolledtext.ScrolledText(encrypted_tab, wrap=tk.WORD, height=2)
        self.encrypted_content_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Add buttons for encrypted view
        encrypted_btn_frame = ttk.Frame(encrypted_tab)
        encrypted_btn_frame.pack(fill='x', pady=5)
        
        ttk.Button(encrypted_btn_frame, text="Copy Encrypted Text", 
                  command=self.copy_encrypted_content).pack(side='left', padx=5)
        ttk.Button(encrypted_btn_frame, text="Show as Hex", 
                  command=self.show_hex_representation).pack(side='left', padx=5)
        ttk.Button(encrypted_btn_frame, text="Show as Base64", 
                  command=self.show_base64_representation).pack(side='left', padx=5)
        ttk.Button(encrypted_btn_frame, text="Clear", style='Warning.TButton',
                  command=lambda: self.encrypted_content_text.delete('1.0', tk.END)).pack(side='left', padx=5)
        
        # Decrypted content tab
        decrypted_tab = ttk.Frame(content_notebook)
        content_notebook.add(decrypted_tab, text="🔓 Decrypted View")
        
        self.decrypted_content_text = scrolledtext.ScrolledText(decrypted_tab, wrap=tk.WORD, height=2)
        self.decrypted_content_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Add buttons for decrypted view
        decrypted_btn_frame = ttk.Frame(decrypted_tab)
        decrypted_btn_frame.pack(fill='x', pady=5)
        
        ttk.Button(decrypted_btn_frame, text="Copy Decrypted Text", 
                  command=self.copy_decrypted_content).pack(side='left', padx=5)
        ttk.Button(decrypted_btn_frame, text="Save to File", 
                  command=self.save_decrypted_content).pack(side='left', padx=5)
        ttk.Button(decrypted_btn_frame, text="Clear", style='Warning.TButton',
                  command=lambda: self.decrypted_content_text.delete('1.0', tk.END)).pack(side='left', padx=5)
        
        # Store current file data for preview
        self.current_shared_file_data = None
        self.current_share_id = None
        self.current_decrypted_content = None
        
        # Load received files
        self.refresh_received_files()
    
    def clear_share_password(self):
        self.share_password.delete(0, tk.END)
        self.share_password_confirm.delete(0, tk.END)
    
    def clear_share_hybrid_keys(self):
        self.share_public_key_text.delete('1.0', tk.END)
        self.share_private_key_text.delete('1.0', tk.END)
    
    def clear_share_all(self):
        self.share_file_path_var.set("")
        self.recipient_email.delete(0, tk.END)
        self.clear_share_password()
        self.clear_share_hybrid_keys()
        self.sharing_status_text.delete('1.0', tk.END)
        self.one_time_var.set(False)
    
    def clear_received_fields(self):
        self.decrypt_password.delete(0, tk.END)
        self.decrypt_key.delete(0, tk.END)
        self.decrypt_iv.delete(0, tk.END)
        self.decrypt_private_key.delete('1.0', tk.END)
        self.encrypted_content_text.delete('1.0', tk.END)
        self.decrypted_content_text.delete('1.0', tk.END)
    
    def clear_decryption_credentials(self):
        self.decrypt_password.delete(0, tk.END)
        self.decrypt_key.delete(0, tk.END)
        self.decrypt_iv.delete(0, tk.END)
        self.decrypt_private_key.delete('1.0', tk.END)
    
    def toggle_encryption_method(self, *args):
        """Toggle between password and key/IV frames"""
        method = self.enc_method_var.get()
        if method == 'password':
            self.password_frame.grid()
            self.key_frame.grid_remove()
        else:
            self.password_frame.grid_remove()
            self.key_frame.grid()
    
    def toggle_share_encryption_method(self):
        """Toggle between symmetric and hybrid encryption in file sharing"""
        method = self.share_enc_method.get()
        if method == 'symmetric':
            # Show symmetric fields, hide hybrid
            self.share_password_frame.grid()
            self.share_hybrid_keys_frame.pack_forget()
        else:
            # Show hybrid fields, hide symmetric
            self.share_password_frame.grid_remove()
            self.share_hybrid_keys_frame.pack(fill='both', expand=True, pady=5)
    
    def toggle_decryption_fields(self):
        """Toggle between password, key/iv, and private key decryption fields"""
        method = self.decrypt_type_var.get()
        
        # Hide all frames first
        self.password_decrypt_frame.pack_forget()
        self.key_iv_decrypt_frame.pack_forget()
        self.private_key_decrypt_frame.pack_forget()
        
        # Show the selected frame
        if method == 'password':
            self.password_decrypt_frame.pack(fill='x', pady=5)
        elif method == 'key/iv':
            self.key_iv_decrypt_frame.pack(fill='x', pady=5)
        elif method == 'private_key':
            self.private_key_decrypt_frame.pack(fill='x', pady=5)
    
    def browse_file(self, path_var):
        filename = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), 
                      ("PDF files", "*.pdf"), ("Image files", "*.jpg *.png *.gif")]
        )
        if filename:
            path_var.set(filename)
    
    def generate_file_key_iv(self):
        algorithm = self.file_algo_var.get()
        key, iv = SymmetricCrypto.generate_key_iv(algorithm)
        self.file_key_entry.delete(0, tk.END)
        self.file_key_entry.insert(0, base64.b64encode(key).decode())
        self.file_iv_entry.delete(0, tk.END)
        self.file_iv_entry.insert(0, base64.b64encode(iv).decode())
    
    def generate_share_hybrid_keys(self):
        """Generate RSA key pair for file sharing hybrid encryption"""
        try:
            private_key, public_key = AsymmetricCrypto.generate_rsa_keypair(2048)
            
            priv_pem = AsymmetricCrypto.key_to_pem(private_key=private_key)
            pub_pem = AsymmetricCrypto.key_to_pem(public_key=public_key)
            
            self.share_public_key_text.delete('1.0', tk.END)
            self.share_public_key_text.insert('1.0', pub_pem)
            self.share_private_key_text.delete('1.0', tk.END)
            self.share_private_key_text.insert('1.0', priv_pem)
            
            self.sharing_status_text.delete('1.0', tk.END)
            self.sharing_status_text.insert('1.0', "✓ RSA keypair generated!\n\nIMPORTANT: Copy the private key and share it with the recipient for decryption.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Key generation failed: {str(e)}")
    
    def encrypt_selected_file(self):
        file_path = self.file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        algorithm = self.file_algo_var.get()
        mode = self.file_mode_var.get()
        method = self.enc_method_var.get()
        
        try:
            if method == 'password':
                password = self.file_password.get()
                confirm = self.file_password_confirm.get()
                
                if not password:
                    messagebox.showerror("Error", "Please enter a password")
                    return
                
                if password != confirm:
                    messagebox.showerror("Error", "Passwords do not match")
                    return
                
                encrypted_data = FileCrypto.encrypt_file_symmetric(
                    file_path, algorithm, mode, password=password
                )
                
            else:  # key method
                key = self.file_key_entry.get()
                iv = self.file_iv_entry.get()
                
                if not key:
                    messagebox.showerror("Error", "Please enter a key")
                    return
                
                encrypted_data = FileCrypto.encrypt_file_symmetric(
                    file_path, algorithm, mode, key=key, iv=iv
                )
            
            self.current_encrypted_file = encrypted_data
            self.current_encryption_method = method
            
            file_size = os.path.getsize(file_path)
            encrypted_size = len(encrypted_data)
            
            status = f"""=== FILE ENCRYPTION SUCCESSFUL ===
Original File: {os.path.basename(file_path)}
Encryption: {algorithm}-{mode} ({method})
Original Size: {file_size:,} bytes
Encrypted Size: {encrypted_size:,} bytes
Compression: {(encrypted_size/file_size)*100:.1f}% of original

File has been encrypted successfully.
You can now save it or share it with another user.
"""
            self.file_status_text.delete('1.0', tk.END)
            self.file_status_text.insert('1.0', status)
            
            self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'file_encryption')
            
        except Exception as e:
            messagebox.showerror("Error", f"File encryption failed: {str(e)}")
    
    def decrypt_selected_file(self):
        encrypted_file = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if not encrypted_file:
            return
        
        try:
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Try to determine encryption method
            try:
                package = pickle.loads(encrypted_data)
                method = package.get('encryption_method', 'password')
            except:
                method = 'password'  # Default to password
            
            if method == 'password':
                password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
                if not password:
                    return
                
                file_data, filename = FileCrypto.decrypt_file_symmetric(
                    encrypted_data, password=password
                )
                
            else:  # key method
                key = simpledialog.askstring("Key", "Enter decryption key (Base64):")
                if not key:
                    return
                
                file_data, filename = FileCrypto.decrypt_file_symmetric(
                    encrypted_data, key=key
                )
            
            # Ask where to save the decrypted file
            save_path = filedialog.asksaveasfilename(
                title="Save decrypted file",
                initialfile=filename,
                defaultextension=os.path.splitext(filename)[1]
            )
            
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                
                self.security_monitor.log_event('successful_decrypt', {'filename': filename})
                messagebox.showinfo("Success", f"File decrypted and saved as:\n{save_path}")
                
                status = f"""=== FILE DECRYPTION SUCCESSFUL ===
Original File: {filename}
Saved As: {os.path.basename(save_path)}
File Size: {len(file_data):,} bytes
Decryption completed successfully.
"""
                self.file_status_text.delete('1.0', tk.END)
                self.file_status_text.insert('1.0', status)
                
        except Exception as e:
            self.security_monitor.log_event('failed_decrypt', {'error': str(e)})
            messagebox.showerror("Error", f"File decryption failed: {str(e)}")
    
    def save_encrypted_file(self):
        if not hasattr(self, 'current_encrypted_file') or not self.current_encrypted_file:
            messagebox.showerror("Error", "No encrypted file to save. Please encrypt a file first.")
            return
        
        save_path = filedialog.asksaveasfilename(
            title="Save encrypted file",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(self.current_encrypted_file)
            
            messagebox.showinfo("Success", f"Encrypted file saved as:\n{save_path}")
    
    def hybrid_encrypt_file(self):
        file_path = self.hybrid_file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        public_key_pem = self.hybrid_pub_key_text.get('1.0', tk.END).strip()
        if not public_key_pem:
            messagebox.showerror("Error", "Please generate or enter a public key")
            return
        
        try:
            encrypted_data = FileCrypto.encrypt_file_hybrid(file_path, public_key_pem)
            
            self.current_hybrid_encrypted_file = encrypted_data
            
            file_size = os.path.getsize(file_path)
            encrypted_size = len(encrypted_data)
            
            status = f"""=== HYBRID FILE ENCRYPTION SUCCESSFUL ===
Original File: {os.path.basename(file_path)}
Encryption: AES-GCM-RSA-Hybrid
Original Size: {file_size:,} bytes
Encrypted Size: {encrypted_size:,} bytes
Compression: {(encrypted_size/file_size)*100:.1f}% of original

File has been encrypted with hybrid encryption.
The symmetric key is encrypted with RSA public key.
"""
            self.hybrid_status_text.delete('1.0', tk.END)
            self.hybrid_status_text.insert('1.0', status)
            
            self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'file_encryption')
            
        except Exception as e:
            messagebox.showerror("Error", f"Hybrid file encryption failed: {str(e)}")
    
    def hybrid_decrypt_file(self):
        encrypted_file = filedialog.askopenfilename(
            title="Select hybrid encrypted file",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if not encrypted_file:
            return
        
        private_key_pem = self.hybrid_priv_key_text.get('1.0', tk.END).strip()
        if not private_key_pem:
            messagebox.showerror("Error", "Please enter your private key")
            return
        
        try:
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            file_data, filename = FileCrypto.decrypt_file_hybrid(encrypted_data, private_key_pem)
            
            # Ask where to save the decrypted file
            save_path = filedialog.asksaveasfilename(
                title="Save decrypted file",
                initialfile=filename,
                defaultextension=os.path.splitext(filename)[1]
            )
            
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(file_data)
                
                self.security_monitor.log_event('successful_decrypt', {'filename': filename, 'type': 'hybrid'})
                messagebox.showinfo("Success", f"File decrypted and saved as:\n{save_path}")
                
                status = f"""=== HYBRID FILE DECRYPTION SUCCESSFUL ===
Original File: {filename}
Saved As: {os.path.basename(save_path)}
File Size: {len(file_data):,} bytes
Decryption completed successfully.
"""
                self.hybrid_status_text.delete('1.0', tk.END)
                self.hybrid_status_text.insert('1.0', status)
                
        except Exception as e:
            self.security_monitor.log_event('failed_decrypt', {'error': str(e), 'type': 'hybrid'})
            messagebox.showerror("Error", f"Hybrid file decryption failed: {str(e)}")
    
    def save_hybrid_encrypted_file(self):
        if not hasattr(self, 'current_hybrid_encrypted_file') or not self.current_hybrid_encrypted_file:
            messagebox.showerror("Error", "No hybrid encrypted file to save. Please encrypt a file first.")
            return
        
        save_path = filedialog.asksaveasfilename(
            title="Save hybrid encrypted file",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
        )
        
        if save_path:
            with open(save_path, 'wb') as f:
                f.write(self.current_hybrid_encrypted_file)
            
            messagebox.showinfo("Success", f"Hybrid encrypted file saved as:\n{save_path}")
    
    def share_current_file(self):
        if not hasattr(self, 'current_encrypted_file') or not self.current_encrypted_file:
            messagebox.showerror("Error", "No file to share. Please encrypt a file first.")
            return
        
        # Open a dialog to select recipient
        share_window = tk.Toplevel(self.root)
        share_window.title("Share File")
        share_window.geometry("500x400")
        
        ttk.Label(share_window, text="Share Encrypted File", font=('Arial', 12, 'bold')).pack(pady=10)
        
        ttk.Label(share_window, text=" 🧑Recipient User:").pack(pady=5)
        recipient_entry = ttk.Entry(share_window, width=40)
        recipient_entry.pack(pady=5)
        
        # Get all users for dropdown
        users = self.user_manager.get_all_users()
        current_user_email = self.user_manager.current_user['email']
        user_emails = [email for email in users.keys() if email != current_user_email]
        
        if user_emails:
            ttk.Label(share_window, text="Or Select from Users:").pack(pady=5)
            recipient_combo = ttk.Combobox(share_window, values=user_emails, width=38)
            recipient_combo.pack(pady=5)
            recipient_combo.bind('<<ComboboxSelected>>', 
                                lambda e: recipient_entry.delete(0, tk.END) or 
                                          recipient_entry.insert(0, recipient_combo.get()))
        
        # One-time download option
        one_time_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(share_window, text="🔒 One-time download link (file self-destructs after first view/download)",
                       variable=one_time_var).pack(pady=10)
        
        ttk.Label(share_window, text="Message (optional):").pack(pady=5)
        message_entry = scrolledtext.ScrolledText(share_window, height=3)
        message_entry.pack(pady=5)
        
        def share_file_action():
            recipient = recipient_entry.get()
            message = message_entry.get('1.0', tk.END).strip()
            one_time = one_time_var.get()
            
            if not recipient:
                messagebox.showerror("Error", "Please enter Recipient User")
                return
            
            if '@' not in recipient or '.' not in recipient:
                messagebox.showerror("Error", "Invalid email format")
                return
            
            # Check if recipient exists
            recipient_user = self.user_manager.get_user_by_email(recipient)
            if not recipient_user:
                messagebox.showerror("Error", "Recipient not found in system")
                return
            
            try:
                metadata = {
                    'sender': self.user_manager.current_user['email'],
                    'sender_name': self.user_manager.current_user['username'],
                    'message': message,
                    'encryption_method': self.current_encryption_method,
                    'algorithm': self.file_algo_var.get(),
                    'mode': self.file_mode_var.get(),
                    'timestamp': time.time(),
                    'one_time': one_time
                }
                
                share_id = self.file_sharing.share_file(
                    self.user_manager.current_user['email'],
                    recipient,
                    self.current_encrypted_file,
                    metadata,
                    one_time=one_time
                )
                
                share_window.destroy()
                
                if one_time:
                    messagebox.showinfo("Success", f"File shared successfully with {recipient}!\nShare ID: {share_id}\n\n⚠️ This is a ONE-TIME download link. The file will self-destruct after first access.")
                else:
                    messagebox.showinfo("Success", f"File shared successfully with {recipient}!\nShare ID: {share_id}")
                
                self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'file_sharing')
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to share file: {str(e)}")
        
        ttk.Button(share_window, text="📤 Share File", style='Success.TButton',
                  command=share_file_action).pack(pady=10)
    
    def share_hybrid_file(self):
        if not hasattr(self, 'current_hybrid_encrypted_file') or not self.current_hybrid_encrypted_file:
            messagebox.showerror("Error", "No hybrid file to share. Please encrypt a file first.")
            return
        
        # Open a dialog to select recipient
        share_window = tk.Toplevel(self.root)
        share_window.title("Share Hybrid File")
        share_window.geometry("500x400")
        
        ttk.Label(share_window, text="Share Hybrid Encrypted File", font=('Arial', 12, 'bold')).pack(pady=10)
        
        ttk.Label(share_window, text="Recipient User:").pack(pady=5)
        recipient_entry = ttk.Entry(share_window, width=40)
        recipient_entry.pack(pady=5)
        
        # Get all users for dropdown
        users = self.user_manager.get_all_users()
        current_user_email = self.user_manager.current_user['email']
        user_emails = [email for email in users.keys() if email != current_user_email]
        
        if user_emails:
            ttk.Label(share_window, text="Or Select from Users:").pack(pady=5)
            recipient_combo = ttk.Combobox(share_window, values=user_emails, width=38)
            recipient_combo.pack(pady=5)
            recipient_combo.bind('<<ComboboxSelected>>', 
                                lambda e: recipient_entry.delete(0, tk.END) or 
                                          recipient_entry.insert(0, recipient_combo.get()))
        
        # One-time download option
        one_time_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(share_window, text="🔒 One-time download link (file self-destructs after first view/download)",
                       variable=one_time_var).pack(pady=10)
        
        ttk.Label(share_window, text="Note: Recipient will need their private key to decrypt").pack(pady=5)
        
        def share_file_action():
            recipient = recipient_entry.get()
            one_time = one_time_var.get()
            
            if not recipient:
                messagebox.showerror("Error", "Please enter Recipient User")
                return
            
            if '@' not in recipient or '.' not in recipient:
                messagebox.showerror("Error", "Invalid email format")
                return
            
            # Check if recipient exists
            recipient_user = self.user_manager.get_user_by_email(recipient)
            if not recipient_user:
                messagebox.showerror("Error", "Recipient not found in system")
                return
            
            try:
                metadata = {
                    'sender': self.user_manager.current_user['email'],
                    'sender_name': self.user_manager.current_user['username'],
                    'encryption_method': 'hybrid',
                    'algorithm': 'AES-GCM-RSA-Hybrid',
                    'timestamp': time.time(),
                    'one_time': one_time
                }
                
                share_id = self.file_sharing.share_file(
                    self.user_manager.current_user['email'],
                    recipient,
                    self.current_hybrid_encrypted_file,
                    metadata,
                    one_time=one_time
                )
                
                share_window.destroy()
                
                if one_time:
                    messagebox.showinfo("Success", f"Hybrid file shared successfully with {recipient}!\nShare ID: {share_id}\n\n⚠️ This is a ONE-TIME download link. The file will self-destruct after first access.")
                else:
                    messagebox.showinfo("Success", f"Hybrid file shared successfully with {recipient}!\nShare ID: {share_id}")
                
                self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'file_sharing')
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to share file: {str(e)}")
        
        ttk.Button(share_window, text="📤 Share Hybrid File", style='Success.TButton',
                  command=share_file_action).pack(pady=10)
    
    def share_file(self):
        file_path = self.share_file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        recipient = self.recipient_email.get()
        if not recipient:
            messagebox.showerror("Error", "Please enter Recipient User")
            return
        
        if '@' not in recipient or '.' not in recipient:
            messagebox.showerror("Error", "Invalid email format")
            return
        
        # Check if recipient exists
        recipient_user = self.user_manager.get_user_by_email(recipient)
        if not recipient_user:
            messagebox.showerror("Error", "Recipient not found in system")
            return
        
        encryption_method = self.share_enc_method.get()
        one_time = self.one_time_var.get()
        
        try:
            if encryption_method == 'symmetric':
                password = self.share_password.get()
                confirm = self.share_password_confirm.get()
                
                if not password:
                    messagebox.showerror("Error", "Please enter a password")
                    return
                
                if password != confirm:
                    messagebox.showerror("Error", "Passwords do not match")
                    return
                
                # Encrypt with password
                encrypted_data = FileCrypto.encrypt_file_symmetric(
                    file_path, 'AES', 'GCM', password=password
                )
                
                metadata = {
                    'sender': self.user_manager.current_user['email'],
                    'sender_name': self.user_manager.current_user['username'],
                    'encryption_method': 'symmetric_password',
                    'algorithm': 'AES-GCM',
                    'timestamp': time.time(),
                    'one_time': one_time
                }
                
            else:  # hybrid
                # Get the public key from the text widget
                public_key_pem = self.share_public_key_text.get('1.0', tk.END).strip()
                if not public_key_pem:
                    messagebox.showerror("Error", "Please generate RSA keys first")
                    return
                
                encrypted_data = FileCrypto.encrypt_file_hybrid(file_path, public_key_pem)
                
                metadata = {
                    'sender': self.user_manager.current_user['email'],
                    'sender_name': self.user_manager.current_user['username'],
                    'encryption_method': 'hybrid',
                    'algorithm': 'AES-GCM-RSA-Hybrid',
                    'timestamp': time.time(),
                    'one_time': one_time,
                    'note': 'Recipient needs the private key to decrypt'
                }
            
            share_id = self.file_sharing.share_file(
                self.user_manager.current_user['email'],
                recipient,
                encrypted_data,
                metadata,
                one_time=one_time
            )
            
            # Get private key for display if hybrid
            private_key_info = ""
            if encryption_method == 'hybrid':
                private_key_pem = self.share_private_key_text.get('1.0', tk.END).strip()
                if private_key_pem:
                    # Show first and last 50 chars of private key
                    if len(private_key_pem) > 100:
                        private_key_preview = private_key_pem[:50] + "..." + private_key_pem[-50:]
                    else:
                        private_key_preview = private_key_pem
                    private_key_info = f"\n\nPRIVATE KEY (for decryption):\n{private_key_preview}"
            
            if one_time:
                messagebox.showinfo("Success", 
                    f"File shared successfully with {recipient}!\n"
                    f"Share ID: {share_id}\n"
                    f"Encryption: {encryption_method}\n"
                    f"⚠️ This is a ONE-TIME download link.{private_key_info}")
            else:
                messagebox.showinfo("Success", 
                    f"File shared successfully with {recipient}!\n"
                    f"Share ID: {share_id}\n"
                    f"Encryption: {encryption_method}{private_key_info}")
            
            self.sharing_status_text.delete('1.0', tk.END)
            status_msg = f"File shared with {recipient}\nShare ID: {share_id}\nEncryption: {encryption_method}"
            if one_time:
                status_msg += "\n⚠️ ONE-TIME download link"
            self.sharing_status_text.insert('1.0', status_msg)
            
            self.user_manager.update_user_operation(self.user_manager.current_user['email'], 'file_sharing')
            
            # Refresh received files to update stats
            self.refresh_received_files()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to share file: {str(e)}")
    
    def preview_original_file(self):
        """Preview the original content of a file before sharing"""
        file_path = self.share_file_path_var.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        try:
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > 1024 * 1024:  # 1MB limit for preview
                messagebox.showwarning("Large File", 
                    "File is too large to preview. Only showing first 1KB.")
                preview_size = 1024
            else:
                preview_size = file_size
            
            with open(file_path, 'rb') as f:
                content = f.read(preview_size)
            
            # Try to decode as text
            try:
                text_content = content.decode('utf-8')
                is_text = True
            except:
                text_content = f"Binary file (first {len(content)} bytes shown as hex)"
                hex_content = content.hex()
                # Format hex for display
                formatted_hex = ' '.join([hex_content[i:i+2] for i in range(0, min(64, len(hex_content)), 2)])
                if len(hex_content) > 64:
                    formatted_hex += "..."
                text_content = f"Binary file (first {len(content)} bytes):\n{formatted_hex}"
                is_text = False
            
            # Create preview window
            preview_window = tk.Toplevel(self.root)
            preview_window.title(f"Preview: {os.path.basename(file_path)}")
            preview_window.geometry("600x400")
            
            ttk.Label(preview_window, text=f"File: {os.path.basename(file_path)}", 
                     font=('Arial', 10, 'bold')).pack(pady=5)
            
            if is_text:
                ttk.Label(preview_window, text="Text Content Preview:").pack(pady=5)
                text_area = scrolledtext.ScrolledText(preview_window, wrap=tk.WORD, width=70, height=20)
                text_area.pack(padx=10, pady=5, fill='both', expand=True)
                text_area.insert('1.0', text_content)
                if file_size > preview_size:
                    text_area.insert(tk.END, f"\n\n... [File truncated, total size: {file_size:,} bytes]")
            else:
                ttk.Label(preview_window, text="Binary File Preview:").pack(pady=5)
                text_area = scrolledtext.ScrolledText(preview_window, wrap=tk.WORD, width=70, height=20)
                text_area.pack(padx=10, pady=5, fill='both', expand=True)
                text_area.insert('1.0', text_content)
                if file_size > preview_size:
                    text_area.insert(tk.END, f"\n\n... [File truncated, total size: {file_size:,} bytes]")
            
            text_area.config(state='disabled')
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to preview file: {str(e)}")
    
    def refresh_received_files(self):
        """Refresh the list of received files"""
        # Clear the tree
        for item in self.received_tree.get_children():
            self.received_tree.delete(item)
        
        # Get current user's received files
        current_user_email = self.user_manager.current_user['email']
        shared_files = self.file_sharing.get_shared_files(current_user_email)
        
        if not shared_files:
            self.sharing_status_text.delete('1.0', tk.END)
            self.sharing_status_text.insert('1.0', "No files shared with you yet.")
            # Update stats
            stats = self.file_sharing.get_share_stats()
            self.share_stats_label.config(text=f"Total: {stats['total_shares']} | One-time: {stats['one_time_shares']}")
            return
        
        # Add files to tree
        for share_id, file_data in shared_files.items():
            sender = file_data['sender']
            metadata = file_data.get('metadata', {})
            timestamp = file_data.get('timestamp', time.time())
            viewed = file_data.get('viewed', False)
            downloaded = file_data.get('downloaded', False)
            one_time = file_data.get('one_time', False)
            corrupted = file_data.get('corrupted', False)
            
            # Try to get filename from metadata
            filename = metadata.get('original_filename', 'Unknown')
            if not filename or filename == 'Unknown':
                # Try to extract from encrypted data
                try:
                    encrypted_data = base64.b64decode(file_data['encrypted_data_b64'])
                    package = pickle.loads(encrypted_data)
                    filename = package.get('original_filename', 'Unknown')
                except:
                    filename = 'Encrypted File'
            
            date_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')
            
            # Get encryption type from metadata
            enc_type = metadata.get('encryption_method', 'symmetric')
            if enc_type == 'symmetric_password':
                enc_display = "Symmetric"
            elif enc_type == 'key':
                enc_display = "Key/IV"
            elif enc_type == 'hybrid':
                enc_display = "Hybrid"
            else:
                enc_display = "Unknown"
            
            one_time_display = "Yes" if one_time else "No"
            if corrupted:
                one_time_display = "Used"
            
            values = (share_id[:12] + '...', sender, filename, date_str, enc_display, one_time_display)
            self.received_tree.insert('', 'end', values=values, iid=share_id)
        
        # Update stats
        stats = self.file_sharing.get_share_stats()
        self.share_stats_label.config(text=f"Total: {stats['total_shares']} | One-time: {stats['one_time_shares']} | Active: {stats['active_shares']}")
        
        self.sharing_status_text.delete('1.0', tk.END)
        self.sharing_status_text.insert('1.0', f"Found {len(shared_files)} file(s) shared with you.\nOne-time downloads: {stats['one_time_shares']}")
    
    def get_selected_share_id(self):
        """Get the selected share ID from the tree"""
        selection = self.received_tree.selection()
        if selection:
            return selection[0]
        return None
    
    def view_received_file_details(self):
        """View detailed information about a received file"""
        share_id = self.get_selected_share_id()
        if not share_id:
            messagebox.showwarning("No Selection", "Please select a file first")
            return
        
        current_user_email = self.user_manager.current_user['email']
        file_data = self.file_sharing.get_shared_file(current_user_email, share_id)
        
        if not file_data:
            messagebox.showerror("Error", "File not found or has been corrupted (one-time download already used)")
            return
        
        # Mark as viewed
        self.file_sharing.mark_as_viewed(current_user_email, share_id)
        
        details_window = tk.Toplevel(self.root)
        details_window.title(f"File Details - {share_id[:12]}...")
        details_window.geometry("500x450")
        
        text_area = scrolledtext.ScrolledText(details_window, wrap=tk.WORD, width=60, height=20)
        text_area.pack(padx=10, pady=10, fill='both', expand=True)
        
        metadata = file_data.get('metadata', {})
        timestamp = file_data.get('timestamp', time.time())
        one_time = file_data.get('one_time', False)
        access_count = file_data.get('access_count', 0)
        corrupted = file_data.get('corrupted', False)
        
        # Try to get more info from encrypted data
        try:
            encrypted_data = file_data['encrypted_data']
            package = pickle.loads(encrypted_data)
            algorithm = package.get('algorithm', 'Unknown')
            file_size = package.get('file_size', len(encrypted_data))
            enc_method = package.get('encryption_method', 'Unknown')
        except:
            algorithm = metadata.get('algorithm', 'Unknown')
            file_size = len(encrypted_data)
            enc_method = metadata.get('encryption_method', 'Unknown')
        
        details = f"""
=== FILE DETAILS ===
Share ID: {share_id}
From: {file_data['sender']}
Date: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}
One-Time Download: {'Yes' if one_time else 'No'}
Access Count: {access_count}
Status: {'Corrupted (already used)' if corrupted else 'Active'}

--- FILE INFORMATION ---
Encryption Method: {enc_method}
Algorithm: {algorithm}
Original File Size: {file_size:,} bytes
Encrypted Size: {len(encrypted_data):,} bytes

--- METADATA ---
Sender Name: {metadata.get('sender_name', 'Unknown')}
Message: {metadata.get('message', 'No message')}

--- INSTRUCTIONS ---
"""
        if corrupted:
            details += "⚠️ This file has been corrupted (one-time download already used).\nYou cannot access this file anymore."
        elif one_time:
            details += "⚠️ This is a ONE-TIME download link.\nThe file will self-destruct after first successful access."
        
        if enc_method == 'symmetric_password':
            details += "\nThis file is encrypted with a password.\nYou will need the password to decrypt it."
        elif enc_method == 'key':
            details += "\nThis file uses key/IV encryption.\nYou will need the key and IV to decrypt it."
        elif enc_method == 'hybrid':
            details += "\nThis file uses hybrid encryption.\nYou will need the private key to decrypt it."
        else:
            details += "\nDecryption method unknown. Please contact the sender."
        
        text_area.insert('1.0', details)
        text_area.config(state='disabled')
        
        # Store current file data for preview
        self.current_shared_file_data = file_data
        self.current_share_id = share_id
        
        # Refresh the tree to update status
        self.refresh_received_files()
    
    def preview_encrypted_file(self):
        """Preview the encrypted content of a received file"""
        share_id = self.get_selected_share_id()
        if not share_id:
            messagebox.showwarning("No Selection", "Please select a file first")
            return
        
        current_user_email = self.user_manager.current_user['email']
        file_data = self.file_sharing.get_shared_file(current_user_email, share_id)
        
        if not file_data:
            messagebox.showerror("Error", "File not found or has been corrupted (one-time download already used)")
            return
        
        # Store current file data
        self.current_shared_file_data = file_data
        self.current_share_id = share_id
        
        # Get encrypted data
        encrypted_data = file_data['encrypted_data']
        
        # Show in encrypted content tab
        self.encrypted_content_text.delete('1.0', tk.END)
        
        # Show as Base64 by default
        encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Truncate if too long
        if len(encoded_data) > 5000:
            preview = encoded_data[:5000] + "\n\n... [Content truncated. Full encrypted data available for decryption]"
        else:
            preview = encoded_data
        
        self.encrypted_content_text.insert('1.0', preview)
        
        # Update status
        one_time = file_data.get('one_time', False)
        corrupted = file_data.get('corrupted', False)
        
        status_msg = f"Encrypted content preview for file {share_id[:12]}...\n"
        status_msg += f"Size: {len(encrypted_data):,} bytes\n"
        
        if corrupted:
            status_msg += "⚠️ This file has been corrupted (one-time download already used).\n"
        elif one_time:
            status_msg += "⚠️ This is a ONE-TIME download link. File will self-destruct after first access.\n"
        
        status_msg += "Note: This is the encrypted data. Decrypt to see original content."
        
        self.sharing_status_text.delete('1.0', tk.END)
        self.sharing_status_text.insert('1.0', status_msg)
    
    def show_hex_representation(self):
        """Show encrypted content as hex"""
        if not self.current_shared_file_data:
            messagebox.showwarning("No File", "Please select a file first")
            return
        
        encrypted_data = self.current_shared_file_data['encrypted_data']
        hex_data = encrypted_data.hex()
        
        # Format hex for display (group bytes)
        formatted_hex = ' '.join([hex_data[i:i+2] for i in range(0, min(1000, len(hex_data)), 2)])
        if len(hex_data) > 1000:
            formatted_hex += " ... [truncated]"
        
        self.encrypted_content_text.delete('1.0', tk.END)
        self.encrypted_content_text.insert('1.0', formatted_hex)
    
    def show_base64_representation(self):
        """Show encrypted content as base64"""
        if not self.current_shared_file_data:
            messagebox.showwarning("No File", "Please select a file first")
            return
        
        encrypted_data = self.current_shared_file_data['encrypted_data']
        encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
        
        # Truncate if too long
        if len(encoded_data) > 5000:
            preview = encoded_data[:5000] + "\n\n... [Content truncated]"
        else:
            preview = encoded_data
        
        self.encrypted_content_text.delete('1.0', tk.END)
        self.encrypted_content_text.insert('1.0', preview)
    
    def copy_encrypted_content(self):
        """Copy encrypted content to clipboard"""
        content = self.encrypted_content_text.get('1.0', tk.END).strip()
        if content:
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("Copied", "Encrypted content copied to clipboard")
        else:
            messagebox.showwarning("No Content", "No encrypted content to copy")
    
    def copy_decrypted_content(self):
        """Copy decrypted content to clipboard"""
        if not self.current_decrypted_content:
            messagebox.showwarning("No Content", "No decrypted content available")
            return
        
        if isinstance(self.current_decrypted_content, bytes):
            try:
                content = self.current_decrypted_content.decode('utf-8')
            except:
                messagebox.showwarning("Binary Content", 
                    "Cannot copy binary content to clipboard. Use 'Save to File' instead.")
                return
        else:
            content = self.current_decrypted_content
        
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("Copied", "Decrypted content copied to clipboard")
    
    def decrypt_and_view_file(self):
        """Decrypt a received file and view its content"""
        share_id = self.get_selected_share_id()
        if not share_id:
            messagebox.showwarning("No Selection", "Please select a file first")
            return
        
        current_user_email = self.user_manager.current_user['email']
        file_data = self.file_sharing.get_shared_file(current_user_email, share_id)
        
        if not file_data:
            messagebox.showerror("Error", "File not found or has been corrupted (one-time download already used)")
            return
        
        # Check if file is corrupted (one-time download already used)
        if file_data.get('corrupted', False):
            messagebox.showerror("Error", "This file has been corrupted (one-time download already used). You cannot access this file anymore.")
            return
        
        try:
            encrypted_data = file_data['encrypted_data']
            package = pickle.loads(encrypted_data)
            enc_method = package.get('encryption_method', 'password')
            
            decryption_type = self.decrypt_type_var.get()
            
            if enc_method == 'password':
                if decryption_type != 'password':
                    # Auto-switch to password type
                    self.decrypt_type_var.set('password')
                    decryption_type = 'password'
                    self.toggle_decryption_fields()
                
                password = self.decrypt_password.get()
                if not password:
                    # Show password dialog
                    password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
                    if not password:
                        return
                
                file_content, filename = FileCrypto.decrypt_file_symmetric(
                    encrypted_data, password=password
                )
                
            elif enc_method == 'key':
                if decryption_type != 'key/iv':
                    # Auto-switch to key/iv type
                    self.decrypt_type_var.set('key/iv')
                    decryption_type = 'key/iv'
                    self.toggle_decryption_fields()
                
                key = self.decrypt_key.get()
                iv = self.decrypt_iv.get()
                
                if not key:
                    # Show key dialog
                    key = simpledialog.askstring("Key", "Enter decryption key (Base64):")
                    if not key:
                        return
                
                file_content, filename = FileCrypto.decrypt_file_symmetric(
                    encrypted_data, key=key
                )
                
            elif enc_method == 'hybrid':
                if decryption_type != 'private_key':
                    # Auto-switch to private_key type
                    self.decrypt_type_var.set('private_key')
                    decryption_type = 'private_key'
                    self.toggle_decryption_fields()
                
                private_key = self.decrypt_private_key.get('1.0', tk.END).strip()
                if not private_key:
                    # Show private key dialog
                    private_key = simpledialog.askstring("Private Key", "Enter your private key (PEM format):")
                    if not private_key:
                        return
                
                file_content, filename = FileCrypto.decrypt_file_hybrid(
                    encrypted_data, private_key
                )
                
            else:
                messagebox.showerror("Error", f"Unknown encryption method: {enc_method}")
                return
            
            # Store decrypted content
            self.current_decrypted_content = file_content
            
            # Display in decrypted content tab
            self.decrypted_content_text.delete('1.0', tk.END)
            
            # Try to decode as text
            try:
                text_content = file_content.decode('utf-8')
                self.decrypted_content_text.insert('1.0', text_content)
                
                # Update status
                status_msg = f"✓ File decrypted successfully!\n"
                status_msg += f"Original filename: {filename}\n"
                status_msg += f"Size: {len(file_content):,} bytes\n"
                status_msg += f"Content type: Text\n"
                status_msg += f"Encryption method: {enc_method}\n"
                
                if file_data.get('one_time', False):
                    status_msg += "⚠️ This was a ONE-TIME download. File has been corrupted for future access.\n"
                
                self.sharing_status_text.delete('1.0', tk.END)
                self.sharing_status_text.insert('1.0', status_msg)
                
                # Log successful decrypt
                self.security_monitor.log_event('successful_decrypt', {'filename': filename, 'share_id': share_id})
                
            except UnicodeDecodeError:
                # Binary file - show hex preview
                hex_content = file_content.hex()
                formatted_hex = ' '.join([hex_content[i:i+2] for i in range(0, min(200, len(hex_content)), 2)])
                if len(hex_content) > 200:
                    formatted_hex += " ... [truncated]"
                
                display_text = f"Binary file: {filename}\n\nHex preview (first 100 bytes):\n{formatted_hex}\n\n"
                display_text += f"Total size: {len(file_content):,} bytes\n"
                display_text += "Use 'Save to File' to save the complete binary file."
                
                self.decrypted_content_text.insert('1.0', display_text)
                
                # Update status
                status_msg = f"✓ File decrypted successfully!\n"
                status_msg += f"Original filename: {filename}\n"
                status_msg += f"Size: {len(file_content):,} bytes\n"
                status_msg += f"Content type: Binary\n"
                status_msg += f"Encryption method: {enc_method}\n"
                
                if file_data.get('one_time', False):
                    status_msg += "⚠️ This was a ONE-TIME download. File has been corrupted for future access.\n"
                
                self.sharing_status_text.delete('1.0', tk.END)
                self.sharing_status_text.insert('1.0', status_msg)
                
                # Log successful decrypt
                self.security_monitor.log_event('successful_decrypt', {'filename': filename, 'share_id': share_id, 'type': 'binary'})
            
            # Refresh the tree
            self.refresh_received_files()
            
        except Exception as e:
            self.security_monitor.log_event('failed_decrypt', {'error': str(e), 'share_id': share_id})
            messagebox.showerror("Error", f"File decryption failed: {str(e)}")
            self.sharing_status_text.delete('1.0', tk.END)
            self.sharing_status_text.insert('1.0', f"❌ Decryption failed: {str(e)}")
    
    def decrypt_and_save_file(self):
        """Decrypt and save a received file to disk"""
        share_id = self.get_selected_share_id()
        if not share_id:
            messagebox.showwarning("No Selection", "Please select a file first")
            return
        
        current_user_email = self.user_manager.current_user['email']
        file_data = self.file_sharing.get_shared_file(current_user_email, share_id)
        
        if not file_data:
            messagebox.showerror("Error", "File not found or has been corrupted (one-time download already used)")
            return
        
        # Check if file is corrupted (one-time download already used)
        if file_data.get('corrupted', False):
            messagebox.showerror("Error", "This file has been corrupted (one-time download already used). You cannot access this file anymore.")
            return
        
        try:
            encrypted_data = file_data['encrypted_data']
            package = pickle.loads(encrypted_data)
            enc_method = package.get('encryption_method', 'password')
            
            decryption_type = self.decrypt_type_var.get()
            
            if enc_method == 'password':
                if decryption_type != 'password':
                    # Auto-switch to password type
                    self.decrypt_type_var.set('password')
                    decryption_type = 'password'
                    self.toggle_decryption_fields()
                
                password = self.decrypt_password.get()
                if not password:
                    password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
                    if not password:
                        return
                
                file_content, filename = FileCrypto.decrypt_file_symmetric(
                    encrypted_data, password=password
                )
                
            elif enc_method == 'key':
                if decryption_type != 'key/iv':
                    # Auto-switch to key/iv type
                    self.decrypt_type_var.set('key/iv')
                    decryption_type = 'key/iv'
                    self.toggle_decryption_fields()
                
                key = self.decrypt_key.get()
                if not key:
                    key = simpledialog.askstring("Key", "Enter decryption key (Base64):")
                    if not key:
                        return
                
                file_content, filename = FileCrypto.decrypt_file_symmetric(
                    encrypted_data, key=key
                )
                
            elif enc_method == 'hybrid':
                if decryption_type != 'private_key':
                    # Auto-switch to private_key type
                    self.decrypt_type_var.set('private_key')
                    decryption_type = 'private_key'
                    self.toggle_decryption_fields()
                
                private_key = self.decrypt_private_key.get('1.0', tk.END).strip()
                if not private_key:
                    private_key = simpledialog.askstring("Private Key", "Enter your private key (PEM format):")
                    if not private_key:
                        return
                
                file_content, filename = FileCrypto.decrypt_file_hybrid(
                    encrypted_data, private_key
                )
                
            else:
                messagebox.showerror("Error", f"Unknown encryption method: {enc_method}")
                return
            
            # Ask where to save the decrypted file
            save_path = filedialog.asksaveasfilename(
                title="Save decrypted file",
                initialfile=filename,
                defaultextension=os.path.splitext(filename)[1] if '.' in filename else ''
            )
            
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(file_content)
                
                # Store decrypted content for viewing
                self.current_decrypted_content = file_content
                
                # Display in decrypted content tab
                self.decrypted_content_text.delete('1.0', tk.END)
                
                # Try to decode as text
                try:
                    text_content = file_content.decode('utf-8')
                    display_text = f"File saved to: {save_path}\n\n"
                    
                    # Add warning for one-time downloads
                    if file_data.get('one_time', False):
                        display_text += "⚠️ This was a ONE-TIME download. File has been corrupted for future access.\n\n"
                    
                    display_text += f"Content preview:\n{text_content[:1000]}"
                    if len(text_content) > 1000:
                        display_text += "\n\n... [content truncated]"
                    
                    self.decrypted_content_text.insert('1.0', display_text)
                except UnicodeDecodeError:
                    # Binary file
                    hex_preview = file_content[:50].hex()
                    formatted_hex = ' '.join([hex_preview[i:i+2] for i in range(0, len(hex_preview), 2)])
                    
                    display_text = f"Binary file saved to: {save_path}\n\n"
                    
                    # Add warning for one-time downloads
                    if file_data.get('one_time', False):
                        display_text += "⚠️ This was a ONE-TIME download. File has been corrupted for future access.\n\n"
                    
                    display_text += f"Hex preview (first 50 bytes):\n{formatted_hex}\n\n"
                    display_text += f"Total size: {len(file_content):,} bytes"
                    
                    self.decrypted_content_text.insert('1.0', display_text)
                
                # Update status
                status_msg = f"✓ File decrypted and saved successfully!\n"
                status_msg += f"Saved as: {save_path}\n"
                status_msg += f"Size: {len(file_content):,} bytes\n"
                status_msg += f"Encryption method: {enc_method}\n"
                
                if file_data.get('one_time', False):
                    status_msg += "⚠️ This was a ONE-TIME download. File has been corrupted for future access.\n"
                
                self.sharing_status_text.delete('1.0', tk.END)
                self.sharing_status_text.insert('1.0', status_msg)
                
                # Log successful decrypt
                self.security_monitor.log_event('successful_decrypt', {'filename': filename, 'share_id': share_id, 'saved_to': save_path})
                
                # Refresh the tree
                self.refresh_received_files()
            
        except Exception as e:
            self.security_monitor.log_event('failed_decrypt', {'error': str(e), 'share_id': share_id})
            messagebox.showerror("Error", f"File decryption failed: {str(e)}")
    
    def save_decrypted_content(self):
        """Save the currently displayed decrypted content to a file"""
        if not self.current_decrypted_content:
            messagebox.showwarning("No Content", "No decrypted content available to save")
            return
        
        # Ask for save location
        save_path = filedialog.asksaveasfilename(
            title="Save decrypted content",
            defaultextension=".txt"
        )
        
        if save_path:
            try:
                if isinstance(self.current_decrypted_content, bytes):
                    with open(save_path, 'wb') as f:
                        f.write(self.current_decrypted_content)
                else:
                    with open(save_path, 'w', encoding='utf-8') as f:
                        f.write(self.current_decrypted_content)
                
                messagebox.showinfo("Success", f"Content saved to:\n{save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
    
    def remove_received_file(self):
        """Remove a received file from the list"""
        share_id = self.get_selected_share_id()
        if not share_id:
            messagebox.showwarning("No Selection", "Please select a file first")
            return
        
        if messagebox.askyesno("Confirm Remove", 
            "Are you sure you want to remove this file from your list?\n"
            "This will not delete the file if it was already saved."):
            
            current_user_email = self.user_manager.current_user['email']
            success = self.file_sharing.remove_shared_file(current_user_email, share_id)
            
            if success:
                messagebox.showinfo("Success", "File removed from your list")
                self.refresh_received_files()
                # Clear content displays
                self.encrypted_content_text.delete('1.0', tk.END)
                self.decrypted_content_text.delete('1.0', tk.END)
                self.current_shared_file_data = None
                self.current_decrypted_content = None
            else:
                messagebox.showerror("Error", "Failed to remove file")
    
    def run(self):
        self.root.mainloop()

class EnhancedCLI:
    def __init__(self):
        self.user_manager = UserManager()
        self.security_monitor = SecurityMonitor()
        self.file_sharing = FileSharingManager()
    
    def run(self):
        parser = argparse.ArgumentParser(description='Enhanced Multi-Algorithm Encryption Suite CLI')
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Auth commands
        auth_parser = subparsers.add_parser('auth', help='Authentication commands')
        auth_subparsers = auth_parser.add_subparsers(dest='auth_command')
        
        register_parser = auth_subparsers.add_parser('register', help='Register new user')
        register_parser.add_argument('--email', required=True, help='User email')
        register_parser.add_argument('--username', required=True, help='Username')
        register_parser.add_argument('--password', required=True, help='Password')
        
        login_parser = auth_subparsers.add_parser('login', help='Login user')
        login_parser.add_argument('--identifier', required=True, help='Email or username')
        login_parser.add_argument('--password', required=True, help='Password')
        
        logout_parser = auth_subparsers.add_parser('logout', help='Logout user')
        
        # Admin commands
        admin_parser = subparsers.add_parser('admin', help='Admin commands')
        admin_subparsers = admin_parser.add_subparsers(dest='admin_command')
        
        list_users_parser = admin_subparsers.add_parser('list-users', help='List all users')
        list_users_parser.add_argument('--csv', action='store_true', help='Output as CSV')
        
        delete_user_parser = admin_subparsers.add_parser('delete-user', help='Delete user')
        delete_user_parser.add_argument('--email', required=True, help='User email to delete')
        
        stats_parser = admin_subparsers.add_parser('stats', help='Show system statistics')
        
        user_stats_parser = admin_subparsers.add_parser('user-stats', help='Show user statistics')
        user_stats_parser.add_argument('--email', required=True, help='User email')
        
        # Security commands
        security_parser = subparsers.add_parser('security', help='Security commands')
        security_subparsers = security_parser.add_subparsers(dest='security_command')
        
        security_stats_parser = security_subparsers.add_parser('stats', help='Show security statistics')
        
        # Encryption commands
        encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt text')
        encrypt_parser.add_argument('--algorithm', choices=['AES', 'DES', '3DES', 'ChaCha20'], required=True)
        encrypt_parser.add_argument('--mode', choices=['CBC', 'CTR', 'GCM'], default='CBC')
        encrypt_parser.add_argument('--text', required=True, help='Text to encrypt')
        encrypt_parser.add_argument('--key', required=True, help='Encryption key (base64)')
        encrypt_parser.add_argument('--iv', help='IV (base64)')
        
        decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt text')
        decrypt_parser.add_argument('--algorithm', choices=['AES', 'DES', '3DES', 'ChaCha20'], required=True)
        decrypt_parser.add_argument('--mode', choices=['CBC', 'CTR', 'GCM'], default='CBC')
        decrypt_parser.add_argument('--text', required=True, help='Text to decrypt')
        decrypt_parser.add_argument('--key', required=True, help='Decryption key (base64)')
        decrypt_parser.add_argument('--iv', help='IV (base64)')
        
        # Hash commands
        hash_parser = subparsers.add_parser('hash', help='Compute hash')
        hash_parser.add_argument('--algorithm', choices=['SHA-256', 'SHA-512', 'SHA3-256'], required=True)
        hash_parser.add_argument('--text', required=True, help='Text to hash')
        
        # File encryption commands
        file_parser = subparsers.add_parser('file', help='File encryption commands')
        file_subparsers = file_parser.add_subparsers(dest='file_command')
        
        encrypt_file_parser = file_subparsers.add_parser('encrypt', help='Encrypt file')
        encrypt_file_parser.add_argument('--input', required=True, help='Input file path')
        encrypt_file_parser.add_argument('--output', help='Output file path (default: input.enc)')
        encrypt_file_parser.add_argument('--algorithm', choices=['AES', 'ChaCha20'], default='AES')
        encrypt_file_parser.add_argument('--mode', choices=['CBC', 'CTR', 'GCM'], default='GCM')
        encrypt_file_parser.add_argument('--password', help='Encryption password')
        encrypt_file_parser.add_argument('--key', help='Encryption key (base64)')
        encrypt_file_parser.add_argument('--iv', help='IV (base64)')
        
        decrypt_file_parser = file_subparsers.add_parser('decrypt', help='Decrypt file')
        decrypt_file_parser.add_argument('--input', required=True, help='Input encrypted file path')
        decrypt_file_parser.add_argument('--output', help='Output file path')
        decrypt_file_parser.add_argument('--password', help='Decryption password')
        decrypt_file_parser.add_argument('--key', help='Decryption key (base64)')
        
        # File sharing commands
        share_parser = subparsers.add_parser('share', help='File sharing commands')
        share_subparsers = share_parser.add_subparsers(dest='share_command')
        
        share_file_parser = share_subparsers.add_parser('send', help='Share file with user')
        share_file_parser.add_argument('--file', required=True, help='File to share')
        share_file_parser.add_argument('--recipient', required=True, help='Recipient User')
        share_file_parser.add_argument('--password', required=True, help='Encryption password')
        share_file_parser.add_argument('--one-time', action='store_true', help='One-time download link')
        
        list_shares_parser = share_subparsers.add_parser('list', help='List shared files')
        list_shares_parser.add_argument('--recipient', help='Filter by Recipient User')
        
        args = parser.parse_args()
        
        if not args.command:
            parser.print_help()
            return
        
        try:
            if args.command == 'auth':
                self.handle_auth(args)
            elif args.command == 'admin':
                self.handle_admin(args)
            elif args.command == 'security':
                self.handle_security(args)
            elif args.command == 'encrypt':
                self.handle_encrypt(args)
            elif args.command == 'decrypt':
                self.handle_decrypt(args)
            elif args.command == 'hash':
                self.handle_hash(args)
            elif args.command == 'file':
                self.handle_file(args)
            elif args.command == 'share':
                self.handle_share(args)
        except Exception as e:
            print(f"Error: {str(e)}")
    
    def handle_auth(self, args):
        if args.auth_command == 'register':
            success, message = self.user_manager.register(args.email, args.username, args.password, args.password)
            print(message)
        elif args.auth_command == 'login':
            success, message = self.user_manager.login(args.identifier, args.password)
            print(message)
            if success:
                self.security_monitor.log_event('successful_login', {'user': args.identifier})
            else:
                self.security_monitor.log_event('failed_login', {'user': args.identifier})
        elif args.auth_command == 'logout':
            success = self.user_manager.logout()
            print("Logged out successfully" if success else "Not logged in")
    
    def handle_admin(self, args):
        if args.admin_command == 'list-users':
            users = self.user_manager.get_all_users()
            if args.csv:
                writer = csv.writer(sys.stdout)
                writer.writerow(['Email', 'Username', 'Admin', 'Status', 'Login Count', 'Failed Attempts', 'Last Login'])
                for email, data in users.items():
                    writer.writerow([
                        email,
                        data.get('username', ''),
                        'Yes' if data.get('is_admin', False) else 'No',
                        'Active' if data.get('active', True) else 'Inactive',
                        data.get('login_count', 0),
                        data.get('failed_attempts', 0),
                        datetime.fromtimestamp(data.get('last_login', 0)).strftime('%Y-%m-%d %H:%M:%S') if data.get('last_login') else 'Never'
                    ])
            else:
                print(f"{'Email':<30} {'Username':<20} {'Admin':<6} {'Status':<8} {'Logins':<6} {'Failed':<6}")
                print("-" * 90)
                for email, data in users.items():
                    print(f"{email:<30} {data.get('username', ''):<20} "
                          f"{'Yes' if data.get('is_admin', False) else 'No':<6} "
                          f"{'Active' if data.get('active', True) else 'Inactive':<8} "
                          f"{data.get('login_count', 0):<6} "
                          f"{data.get('failed_attempts', 0):<6}")
        
        elif args.admin_command == 'delete-user':
            success, message = self.user_manager.delete_user(args.email)
            print(message)
        
        elif args.admin_command == 'stats':
            stats = self.user_manager.get_system_stats()
            print("=== System Statistics ===")
            for key, value in stats.items():
                print(f"{key.replace('_', ' ').title()}: {value}")
        
        elif args.admin_command == 'user-stats':
            user_data = self.user_manager.get_user_by_email(args.email)
            if user_data:
                print(f"=== User Statistics for {args.email} ===")
                print(f"Username: {user_data.get('username', 'N/A')}")
                print(f"Admin: {'Yes' if user_data.get('is_admin', False) else 'No'}")
                print(f"Status: {'Active' if user_data.get('active', True) else 'Inactive'}")
                print(f"Login Count: {user_data.get('login_count', 0)}")
                print(f"Failed Attempts: {user_data.get('failed_attempts', 0)}")
                print(f"Created: {datetime.fromtimestamp(user_data.get('created_at', 0)).strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"Last Login: {datetime.fromtimestamp(user_data.get('last_login', 0)).strftime('%Y-%m-%d %H:%M:%S') if user_data.get('last_login') else 'Never'}")
                
                ops = user_data.get('encryption_operations', {})
                print("\n=== Encryption Operations ===")
                for op_type, count in ops.items():
                    print(f"{op_type.replace('_', ' ').title()}: {count}")
                print(f"Total: {sum(ops.values())}")
            else:
                print(f"User {args.email} not found")
    
    def handle_security(self, args):
        if args.security_command == 'stats':
            stats = self.security_monitor.get_security_stats()
            print("=== Security Statistics ===")
            print(f"Failed Logins: {stats.get('failed_logins', 0)}")
            print(f"Successful Logins: {stats.get('successful_logins', 0)}")
            print(f"Failed Decrypts: {stats.get('failed_decrypts', 0)}")
            print(f"Successful Decrypts: {stats.get('successful_decrypts', 0)}")
            print(f"Brute Force Attempts: {stats.get('brute_force_attempts', 0)}")
            
            print("\n=== Attack Types ===")
            for attack_type, count in stats.get('attack_types', {}).items():
                print(f"{attack_type.replace('_', ' ').title()}: {count}")
            
            print("\n=== Today's Stats ===")
            today = stats.get('today_stats', {})
            for key, value in today.items():
                print(f"{key.replace('_', ' ').title()}: {value}")
    
    def handle_encrypt(self, args):
        key = base64.b64decode(args.key)
        iv = base64.b64decode(args.iv) if args.iv else None
        
        ciphertext = SymmetricCrypto.encrypt_text(args.algorithm, args.mode, args.text, key, iv)
        print(f"Encrypted: {ciphertext}")
    
    def handle_decrypt(self, args):
        key = base64.b64decode(args.key)
        iv = base64.b64decode(args.iv) if args.iv else None
        
        try:
            plaintext = SymmetricCrypto.decrypt_text(args.algorithm, args.mode, args.text, key, iv)
            print(f"Decrypted: {plaintext}")
            self.security_monitor.log_event('successful_decrypt')
        except Exception as e:
            self.security_monitor.log_event('failed_decrypt', {'error': str(e)})
            print(f"Decryption failed: {str(e)}")
    
    def handle_hash(self, args):
        hash_value = HashUtils.compute_hash(args.algorithm, args.text)
        print(f"{args.algorithm}: {hash_value}")
    
    def handle_file(self, args):
        if args.file_command == 'encrypt':
            if not os.path.exists(args.input):
                print(f"Error: Input file '{args.input}' not found")
                return
            
            output = args.output or args.input + '.enc'
            
            try:
                if args.password:
                    encrypted_data = FileCrypto.encrypt_file_symmetric(
                        args.input, args.algorithm, args.mode, password=args.password
                    )
                elif args.key:
                    encrypted_data = FileCrypto.encrypt_file_symmetric(
                        args.input, args.algorithm, args.mode, key=args.key, iv=args.iv
                    )
                else:
                    print("Error: Either --password or --key must be specified")
                    return
                
                with open(output, 'wb') as f:
                    f.write(encrypted_data)
                
                print(f"File encrypted successfully: {output}")
                
            except Exception as e:
                print(f"Encryption failed: {str(e)}")
        
        elif args.file_command == 'decrypt':
            if not os.path.exists(args.input):
                print(f"Error: Input file '{args.input}' not found")
                return
            
            output = args.output or 'decrypted_' + os.path.basename(args.input).replace('.enc', '')
            
            try:
                with open(args.input, 'rb') as f:
                    encrypted_data = f.read()
                
                if args.password:
                    file_data, filename = FileCrypto.decrypt_file_symmetric(
                        encrypted_data, password=args.password
                    )
                elif args.key:
                    file_data, filename = FileCrypto.decrypt_file_symmetric(
                        encrypted_data, key=args.key
                    )
                else:
                    print("Error: Either --password or --key must be specified")
                    return
                
                with open(output, 'wb') as f:
                    f.write(file_data)
                
                self.security_monitor.log_event('successful_decrypt', {'filename': filename})
                print(f"File decrypted successfully: {output} (original: {filename})")
                
            except Exception as e:
                self.security_monitor.log_event('failed_decrypt', {'error': str(e)})
                print(f"Decryption failed: {str(e)}")
    
    def handle_share(self, args):
        if args.share_command == 'send':
            if not os.path.exists(args.file):
                print(f"Error: File '{args.file}' not found")
                return
            
            # Check if recipient exists
            recipient_user = self.user_manager.get_user_by_email(args.recipient)
            if not recipient_user:
                print(f"Error: Recipient '{args.recipient}' not found")
                return
            
            try:
                # Encrypt the file
                encrypted_data = FileCrypto.encrypt_file_symmetric(
                    args.file, 'AES', 'GCM', password=args.password
                )
                
                metadata = {
                    'sender': 'cli_user',
                    'sender_name': 'CLI User',
                    'encryption_method': 'symmetric_password',
                    'algorithm': 'AES-GCM',
                    'timestamp': time.time(),
                    'one_time': args.one_time
                }
                
                share_id = self.file_sharing.share_file(
                    'cli_user',
                    args.recipient,
                    encrypted_data,
                    metadata,
                    one_time=args.one_time
                )
                
                if args.one_time:
                    print(f"File shared successfully with {args.recipient}!")
                    print(f"Share ID: {share_id}")
                    print("⚠️ This is a ONE-TIME download link. The file will self-destruct after first access.")
                else:
                    print(f"File shared successfully with {args.recipient}!")
                    print(f"Share ID: {share_id}")
                
            except Exception as e:
                print(f"Failed to share file: {str(e)}")
        
        elif args.share_command == 'list':
            if args.recipient:
                shared_files = self.file_sharing.get_shared_files(args.recipient)
                print(f"=== Files shared with {args.recipient} ===")
            else:
                # Get all shared files
                try:
                    with open('shared_files.json', 'r') as f:
                        all_files = json.load(f)
                    
                    print("=== All Shared Files ===")
                    for recipient, files in all_files.items():
                        print(f"\nRecipient: {recipient}")
                        for share_id, file_data in files.items():
                            sender = file_data.get('sender', 'Unknown')
                            timestamp = file_data.get('timestamp', time.time())
                            date_str = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M')
                            one_time = file_data.get('one_time', False)
                            corrupted = file_data.get('corrupted', False)
                            
                            status = "Active"
                            if corrupted:
                                status = "Corrupted"
                            
                            print(f"  ID: {share_id[:12]}... | From: {sender} | Date: {date_str} | One-Time: {one_time} | Status: {status}")
                    
                    # Show stats
                    stats = self.file_sharing.get_share_stats()
                    print(f"\n=== Sharing Statistics ===")
                    print(f"Total Shares: {stats['total_shares']}")
                    print(f"One-Time Shares: {stats['one_time_shares']}")
                    print(f"Downloaded Shares: {stats['downloaded_shares']}")
                    print(f"Active Shares: {stats['active_shares']}")
                    
                except Exception as e:
                    print(f"Error reading shared files: {str(e)}")

def main():
    if len(sys.argv) > 1:
        cli = EnhancedCLI()
        cli.run()
    else:
        # Check if required packages are installed
        try:
            import matplotlib
            import numpy as np
            import seaborn as sns
            import psutil
        except ImportError as e:
            print(f"Missing required package: {e}")
            print("Please install required packages: pip install matplotlib numpy seaborn psutil")
            sys.exit(1)
        
        gui = ModernTkinterGUI()
        gui.run()

if __name__ == "__main__":
    main()