# Smash Messaging Endpoint (SMEv1)

![License](https://img.shields.io/badge/license-AGPL--3.0-blue)
![Version](https://img.shields.io/badge/version-0.0.1-alpha)

A reference implementation of the Smash Messaging Endpoint (SMEv1) protocol specification, part of the [Smash Protocol](https://www.smashchats.com/) ecosystem.

## Overview

SMEv1 serves as a relay server responsible for handling signaling session data between Smash Peers and managing asynchronous messaging. It acts as an untrusted intermediary to ensure smooth communication when peers are not directly connected.

### Key Features

- Anonymous user registration with public key authentication
- Challenge-based authentication system
- Secure message relay between registered peers
- Asynchronous message queuing for offline recipients
- WebSocket-based real-time communication
- Health monitoring endpoint

## Getting Started

### Prerequisites

- Node.js 22.x
- npm 10.x
- Docker (optional)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd smash-messaging-endpoint
```

2. Install dependencies:
```bash
npm install
```

3. Generate SME keypair:
```bash
npm run generate-keys
```

4. Start the development server:
```bash
npm run dev
```

### Docker Deployment

Build and run using Docker:

```bash
docker build -t sme-v1 .
docker run -p 3210:3210 \
  -e SME_PUBLIC_KEY="your-public-key" \
  -e SME_PRIVATE_KEY="your-private-key" \
  sme-v1
```

## Development

### Testing

Run the test suite:

```bash
npm test
```

For continuous testing during development:

```bash
npm run test:watch
```

For test coverage report:

```bash
npm run test:coverage
```

## Architecture

SMEv1 implements a WebSocket-based messaging relay with the following key components:

- **Authentication**: Challenge-based public key authentication system
- **Message Queue**: Temporary storage for offline recipient messages
- **Real-time Relay**: WebSocket-based message forwarding for online peers
- **Health Monitoring**: Basic health check endpoint

## Contributing

Please read our [Contributing Guide](./docs/CONTRIBUTING.md) before submitting pull requests. All contributions are subject to our [Code of Conduct](./docs/CODE_OF_CONDUCT.md).

### Development Environment

We recommend using Visual Studio Code with our provided settings and extensions. The repository includes a devcontainer configuration for consistent development environments.

## Security

For security concerns or vulnerability reports, please contact:
- Email: [security@smashchats.com](mailto:security@smashchats.com)

## License

This project is licensed under the GNU Affero General Public License v3.0 with additional terms - see the [LICENSE](./LICENSE) file for details.

## Contact

- Developer Chat: Smash Developers Telegram Group (request access)
- Email: [contribute@smashchats.com](mailto:contribute@smashchats.com)
- Website: [https://www.smashchats.com/](https://www.smashchats.com/)

## Related Projects

- [Smash Protocol](https://github.com/unstaticlabs/smash-node-lib)
- [Smash Simple Neighborhood](https://github.com/unstaticlabs/smash-simple-neighborhood)
