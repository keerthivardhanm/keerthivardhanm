import datetime

# Initialize account details with a default PIN, balance, and empty transaction history
account = {
    'pin': '1234',
    'balance': 1000.0,
    'transaction_history': []
}

def display_menu():
    """Display the ATM main menu options"""
    print("\nATM Menu:")
    print("1. Balance Inquiry")
    print("2. Cash Withdrawal")
    print("3. Cash Deposit")
    print("4. PIN Change")
    print("5. Transaction History")
    print("6. Exit")

def get_current_timestamp():
    """Generate current timestamp in readable format"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def validate_pin():
    """Validate user PIN with 3 attempts allowed"""
    attempts = 3
    while attempts > 0:
        entered_pin = input("Enter your 4-digit PIN: ")
        if entered_pin == account['pin']:
            return True
        attempts -= 1
        print(f"Invalid PIN. {attempts} attempts remaining.")
    print("Too many incorrect attempts. Your card is retained.")
    return False

def atm_simulation():
    """Main ATM simulation function handling user interactions"""
    # PIN Validation
    if not validate_pin():
        return
    
    print("\nWelcome to the ATM!")
    while True:
        display_menu()
        choice = input("Enter your choice (1-6): ")
        
        # Balance Inquiry
        if choice == '1':
            print(f"\nCurrent Balance: ${account['balance']:.2f}")
        
        # Cash Withdrawal
        elif choice == '2':
            try:
                amount = float(input("Enter withdrawal amount: $"))
                if amount <= 0:
                    print("Amount must be positive.")
                elif amount > account['balance']:
                    print("Insufficient funds.")
                else:
                    account['balance'] -= amount
                    transaction = {
                        'type': 'withdrawal',
                        'amount': amount,
                        'timestamp': get_current_timestamp()
                    }
                    account['transaction_history'].append(transaction)
                    print(f"Successfully withdrew ${amount:.2f}")
                    print(f"New Balance: ${account['balance']:.2f}")
            except ValueError:
                print("Invalid amount. Please enter numbers only.")
        
        # Cash Deposit
        elif choice == '3':
            try:
                amount = float(input("Enter deposit amount: $"))
                if amount <= 0:
                    print("Amount must be positive.")
                else:
                    account['balance'] += amount
                    transaction = {
                        'type': 'deposit',
                        'amount': amount,
                        'timestamp': get_current_timestamp()
                    }
                    account['transaction_history'].append(transaction)
                    print(f"Successfully deposited ${amount:.2f}")
                    print(f"New Balance: ${account['balance']:.2f}")
            except ValueError:
                print("Invalid amount. Please enter numbers only.")
        
        # PIN Change
        elif choice == '4':
            old_pin = input("Enter current PIN: ")
            if old_pin != account['pin']:
                print("Incorrect current PIN.")
            else:
                new_pin = input("Enter new 4-digit PIN: ")
                confirm_pin = input("Confirm new PIN: ")
                
                if new_pin != confirm_pin:
                    print("PINs do not match.")
                elif len(new_pin) != 4 or not new_pin.isdigit():
                    print("PIN must be 4 numeric digits.")
                else:
                    account['pin'] = new_pin
                    transaction = {
                        'type': 'pin_change',
                        'timestamp': get_current_timestamp()
                    }
                    account['transaction_history'].append(transaction)
                    print("PIN successfully changed.")
        
        # Transaction History
        elif choice == '5':
            print("\nTransaction History:")
            if not account['transaction_history']:
                print("No transactions yet.")
            else:
                for txn in account['transaction_history']:
                    if txn['type'] == 'withdrawal':
                        print(f"{txn['timestamp']} - Withdrawal: ${txn['amount']:.2f}")
                    elif txn['type'] == 'deposit':
                        print(f"{txn['timestamp']} - Deposit: ${txn['amount']:.2f}")
                    elif txn['type'] == 'pin_change':
                        print(f"{txn['timestamp']} - PIN Changed")
        
        # Exit
        elif choice == '6':
            print("\nThank you for using our ATM. Goodbye!")
            break
        
        else:
            print("Invalid choice. Please select 1-6.")

# Start the ATM simulation
if __name__ == "__main__":
    atm_simulation()