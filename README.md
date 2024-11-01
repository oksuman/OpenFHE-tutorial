# OpenFHE-Tutorial

This repository is designed to help OpenFHE beginners practice and understand the core functionalities of OpenFHE CKKS implementation. 

## Requirements

### Prerequisites
- C++ Compiler (gcc/g++ >= 9.4.0)
- CMake (>= 3.5.1)
- Make
- Git
- OpenFHE Library

### Installing OpenFHE
The OpenFHE library must be installed on your system. You can find:
- Source code: [OpenFHE GitHub Repository](https://github.com/openfheorg/openfhe-development)
- Installation guide: [OpenFHE Documentation](https://openfhe-development.readthedocs.io)

## Getting Started

### Checking Prerequisites
```bash
# Check C++ compiler
g++ --version

# Check CMake version
cmake --version

# Check Make version
make --version

# Check Git version
git --version
```

### Building the Project
1. Clone the repository
```bash
git clone https://github.com/oksuman/OpenFHE-tutorial.git
cd OpenFHE-tutorial
```

2. Create and enter build directory
```bash
mkdir build
cd build
```

3. Configure and build
```bash
cmake ..
make
```

### Running Tutorials
The tutorial examples demonstrate basic CKKS operations:
```bash
# Build and run tutorial1
cd build
make tutorial1
./tutorial/tutorial1

# Build and run tutorial2
make tutorial2
./tutorial/tutorial2
```

### Practice Problems
The practice problems are designed for you to implement specific functionalities:

1. Each practice directory contains:
   - Header file (`.h`) with function declarations
   - Source file (`.cpp`) with TODO implementations
   - Test file for verification

2. To work on practice problems:
   - Implement the required functions in the corresponding `.cpp` files
   - Build and run tests to verify your implementation

3. Building and running tests:
```bash
# Build all tests
cd build
make practice1_test practice2_test practice3_test

# Run individual tests
./test/practice1_test
./test/practice2_test
./test/practice3_test

# Or run all tests
ctest
```

## Project Structure
```
OpenFHE-Tutorial/
├── CMakeLists.txt
├── practice1/        # Practice problem 1
├── practice2/        # Practice problem 2
├── practice3/        # Practice problem 3
├── tutorial/         # Tutorial examples
├── test/            # Test files
└── build/           # Build directory (generated)
```

## Note
- Solutions for practice problems are available in the `solution` branch (`git checkout solution`)