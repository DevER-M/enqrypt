import argparse
import sys
from enqrypt.chat import ChatApp


def main():
    parser = argparse.ArgumentParser(description="MLKEM Quantum-Resistant Chat Encryption Tool")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    parser.add_argument("--init", metavar="USERNAME", help="Initialize chat with username")
    parser.add_argument("--send", nargs=2, metavar=("TO", "MESSAGE"), help="Send message to recipient")
    parser.add_argument("--key", action="store_true", help="Export current user's encapsulation key")
    
    args = parser.parse_args()
    
    if args.demo:
        from enqrypt.chat import demo
        demo()
        return
    
    if args.init:
        chat = ChatApp(args.init)
        print(f"Initialized chat as '{args.init}'")
        print(f"Encapsulation key (share with recipients):")
        print(chat.encaps_key.hex())
        print(f"Decapsulation key (keep secret):")
        print(chat.decaps_key.hex())
        return
    
    print("Use --help for usage information")


if __name__ == "__main__":
    main()