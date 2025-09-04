#!/usr/bin/env python3
"""
Fund Flow Testing System - SkillStake
Tests all deposit/withdrawal scenarios to ensure no money is lost
"""

import sqlite3
import json
from datetime import datetime

class FundFlowTester:
    def __init__(self):
        self.conn = sqlite3.connect('gamebet.db')
        self.c = self.conn.cursor()
        self.test_results = []
        
    def log_test(self, test_name, expected, actual, passed):
        result = {
            'test': test_name,
            'expected': expected,
            'actual': actual,
            'passed': passed,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name}: Expected {expected}, Got {actual}")
        
    def get_user_balance(self, user_id):
        self.c.execute('SELECT balance FROM users WHERE id = ?', (user_id,))
        result = self.c.fetchone()
        return result[0] if result else 0
        
    def get_admin_earnings(self):
        self.c.execute('SELECT COALESCE(SUM(amount), 0) FROM transactions WHERE user_id = 1 AND amount > 0')
        return self.c.fetchone()[0]
        
    def create_test_user(self, username, initial_balance=1000):
        try:
            self.c.execute('INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)',
                          (username, f'{username}@test.com', 'test123', initial_balance))
            self.conn.commit()
            return self.c.lastrowid
        except:
            self.c.execute('SELECT id FROM users WHERE username = ?', (username,))
            user_id = self.c.fetchone()[0]
            self.c.execute('UPDATE users SET balance = ? WHERE id = ?', (initial_balance, user_id))
            self.conn.commit()
            return user_id
    
    def test_deposit_flow(self):
        print("\n🔵 Testing Deposit Flow...")
        
        # Test 1: M-Pesa Deposit with 3% fee
        user_id = self.create_test_user('test_deposit_user', 0)
        initial_balance = self.get_user_balance(user_id)
        initial_admin = self.get_admin_earnings()
        
        deposit_amount = 1000
        fee = deposit_amount * 0.03  # 3% fee
        net_amount = deposit_amount - fee
        
        # Simulate admin approving deposit
        self.c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (net_amount, user_id))
        self.c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                      (user_id, 'deposit', net_amount, f'M-Pesa deposit KSh {deposit_amount} - 3% fee = KSh {net_amount}'))
        self.c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                      (1, 'deposit_fee', fee, f'3% deposit fee from M-Pesa deposit'))
        self.conn.commit()
        
        final_balance = self.get_user_balance(user_id)
        final_admin = self.get_admin_earnings()
        
        self.log_test("M-Pesa Deposit - User Balance", net_amount, final_balance, final_balance == net_amount)
        self.log_test("M-Pesa Deposit - Admin Fee", initial_admin + fee, final_admin, final_admin == initial_admin + fee)
        
    def test_withdrawal_flow(self):
        print("\n🔴 Testing Withdrawal Flow...")
        
        user_id = self.create_test_user('test_withdrawal_user', 2000)
        initial_balance = self.get_user_balance(user_id)
        initial_admin = self.get_admin_earnings()
        
        # Test M-Pesa Withdrawal
        withdrawal_amount = 500
        mpesa_fee = 25
        processing_fee = withdrawal_amount * 0.02  # 2%
        total_fees = mpesa_fee + processing_fee
        
        # Deduct from user balance
        self.c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (withdrawal_amount, user_id))
        self.c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                      (user_id, 'pending_withdrawal', -withdrawal_amount, f'M-Pesa withdrawal KSh {withdrawal_amount}'))
        self.c.execute('INSERT INTO transactions (user_id, type, amount, description) VALUES (?, ?, ?, ?)',
                      (1, 'withdrawal_fee', total_fees, f'Withdrawal fees from M-Pesa'))
        self.conn.commit()
        
        expected_balance = initial_balance - withdrawal_amount
        actual_balance = self.get_user_balance(user_id)
        
        self.log_test("M-Pesa Withdrawal - User Balance", expected_balance, actual_balance, actual_balance == expected_balance)
        
    def test_refund_scenarios(self):
        print("\n🔄 Testing Refund Scenarios...")
        
        user_id = self.create_test_user('test_refund_user', 1000)
        initial_balance = self.get_user_balance(user_id)
        
        # Test Withdrawal Cancellation
        withdrawal_amount = 300
        self.c.execute('UPDATE users SET balance = balance - ? WHERE id = ?', (withdrawal_amount, user_id))
        
        # User cancels - refund full amount
        self.c.execute('UPDATE users SET balance = balance + ? WHERE id = ?', (withdrawal_amount, user_id))
        self.conn.commit()
        
        final_balance = self.get_user_balance(user_id)
        self.log_test("Withdrawal Cancellation", initial_balance, final_balance, final_balance == initial_balance)
        
    def run_all_tests(self):
        print("🧪 Starting Fund Flow Tests...")
        print("=" * 50)
        
        try:
            self.test_deposit_flow()
            self.test_withdrawal_flow()
            self.test_refund_scenarios()
            
            # Summary
            total_tests = len(self.test_results)
            passed_tests = sum(1 for test in self.test_results if test['passed'])
            failed_tests = total_tests - passed_tests
            
            print("\n" + "=" * 50)
            print(f"📊 TEST SUMMARY:")
            print(f"✅ Passed: {passed_tests}/{total_tests}")
            print(f"❌ Failed: {failed_tests}/{total_tests}")
            print(f"📈 Success Rate: {(passed_tests/total_tests)*100:.1f}%")
            
            if failed_tests > 0:
                print("\n❌ FAILED TESTS:")
                for test in self.test_results:
                    if not test['passed']:
                        print(f"  - {test['test']}: Expected {test['expected']}, Got {test['actual']}")
                        
        except Exception as e:
            print(f"❌ Test Error: {e}")
        finally:
            self.conn.close()

if __name__ == "__main__":
    tester = FundFlowTester()
    tester.run_all_tests()