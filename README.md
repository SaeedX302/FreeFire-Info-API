# FreeFire-Api

This project is a Python-based implementation that interacts with Free Fire's internal API using Protocol Buffers for serialization. It handles parsing and construction of protobuf messages defined in the game's network communication schema.

## Project Structure

```
.
├── app.py                         # Main application entry point
├── lib2.py                        # Helper module for logic or protobuf handling
├── proto/
│   ├── AccountPersonalShow_pb2.py  # Compiled proto for account info
│   ├── FreeFire_pb2.py             # Compiled proto for general game APIs
│   └── main_pb2.py                 # Compiled proto combining multiple schema
└── requirements.txt              # Dependencies
```

## Features

- Encode/decode Free Fire API messages using protobuf
- Modular structure for scalable extensions
- Easily extensible to support more `.proto` definitions

## Setup

1. **Install dependencies** (ensure you’re in a Python 3+ environment):

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the project:**

   ```bash
   python app.py
   ```

## Notes

- All `.proto` files have been compiled with `protoc` and stored in `proto/`
- Make sure your Python environment includes `protobuf >= 3.20`

## License

MIT License — free to use, modify, and distribute.

## Example Usage

You can test the API using `curl`:

```bash
curl -X GET 'http://127.0.0.1:3000/api/account?uid=1813014615&region=ind'
```
