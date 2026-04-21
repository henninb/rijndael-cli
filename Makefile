LIBS=-Llib

all: linux

linux:
	@rm -rf *.exe
	@gcc rijndael-c/rijndael-alg-fst.c rijndael-c/rijndael-api-fst.c rijndael-c/rijndael-encrypt.c -o rijndael-encrypt.exe -Irijndael-c $(LIBS) -O2 -Wall -lssl -lcrypto
	@gcc rijndael-c/rijndael-alg-fst.c rijndael-c/rijndael-api-fst.c rijndael-c/rijndael-decrypt.c -o rijndael-decrypt.exe -Irijndael-c $(LIBS) -O2 -Wall -lssl -lcrypto
	@gcc -c rijndael-c/rijndael-alg-fst.c -o /tmp/rijndael-alg-fst.o -Irijndael-c -O2
	@gcc -c rijndael-c/rijndael-api-fst.c -o /tmp/rijndael-api-fst.o -Irijndael-c -O2
	@nasm -f elf64 rijndael-nasm/rijndael-encrypt.asm -o /tmp/rijndael-encrypt-nasm.o
	@gcc -no-pie -o rijndael-encrypt-nasm.exe /tmp/rijndael-encrypt-nasm.o /tmp/rijndael-alg-fst.o /tmp/rijndael-api-fst.o -lssl -lcrypto
	@nasm -f elf64 rijndael-nasm/rijndael-decrypt.asm -o /tmp/rijndael-decrypt-nasm.o
	@gcc -no-pie -o rijndael-decrypt-nasm.exe /tmp/rijndael-decrypt-nasm.o /tmp/rijndael-alg-fst.o /tmp/rijndael-api-fst.o -lssl -lcrypto
	@cd rijndael-java && javac RijndaelEncrypt.java && jar cmf RijndaelEncrypt.mf ../RijndaelEncrypt.jar RijndaelEncrypt.class && rm -f *.class
	@cd rijndael-java && javac RijndaelDecrypt.java && jar cmf RijndaelDecrypt.mf ../RijndaelDecrypt.jar RijndaelDecrypt.class && rm -f *.class
	@pip install -q -r rijndael-python/requirements.txt
	@chmod 755 rijndael-python/rijndael-decrypt.py rijndael-python/rijndael-encrypt.py
	@chmod 755 rijndael-groovy/rijndael-decrypt.groovy rijndael-groovy/rijndael-encrypt.groovy
	@dotnet publish rijndael-csharp/generate-key/generate-key.csproj -c Release -o dotnet-build/generate-key --nologo -v q -p:PublishSingleFile=true
	@cp dotnet-build/generate-key/generate-key generate-key.exe
	@dotnet publish rijndael-csharp/rijndael-mono-decrypt/rijndael-mono-decrypt.csproj -c Release -o dotnet-build/rijndael-mono-decrypt --nologo -v q -p:PublishSingleFile=true
	@cp dotnet-build/rijndael-mono-decrypt/rijndael-mono-decrypt rijndael-mono-decrypt.exe
	@dotnet publish rijndael-csharp/rijndael-mono-encrypt/rijndael-mono-encrypt.csproj -c Release -o dotnet-build/rijndael-mono-encrypt --nologo -v q -p:PublishSingleFile=true
	@cp dotnet-build/rijndael-mono-encrypt/rijndael-mono-encrypt rijndael-mono-encrypt.exe
	@cd rijndael-rust && cargo build --release -q
	@cp rijndael-rust/target/release/rijndael-encrypt rijndael-encrypt-rust.exe
	@cp rijndael-rust/target/release/rijndael-decrypt rijndael-decrypt-rust.exe
	@cd rijndael-go && go build -o ../rijndael-encrypt-go.exe ./rijndael-encrypt/
	@cd rijndael-go && go build -o ../rijndael-decrypt-go.exe ./rijndael-decrypt/
	@cd rijndael-haskell && stack build -j4 --silent
	@cp $$(cd rijndael-haskell && stack path --local-install-root 2>/dev/null | tail -1)/bin/rijndael-encrypt rijndael-encrypt-haskell.exe
	@cp $$(cd rijndael-haskell && stack path --local-install-root 2>/dev/null | tail -1)/bin/rijndael-decrypt rijndael-decrypt-haskell.exe

test: linux
	@echo "=== Python tests (pytest) ==="
	@cd rijndael-python && python3 -m pytest test_rijndael.py -v
	@echo ""
	@echo "=== Go tests ==="
	@cd rijndael-go && go test ./rijndael-encrypt/... ./rijndael-decrypt/... -v
	@echo ""
	@echo "=== Rust tests (cargo test) ==="
	@cd rijndael-rust && cargo test --release -- --test-threads=1
	@echo ""
	@echo "=== Haskell tests (stack test) ==="
	@cd rijndael-haskell && stack test
	@echo ""
	@echo "=== Java tests ==="
	@cd rijndael-java && javac RijndaelTest.java && cd .. && java -cp rijndael-java RijndaelTest
	@echo ""
	@echo "=== C tests ==="
	@gcc rijndael-c/test_rijndael.c -o test_rijndael_c && ./test_rijndael_c
	@echo ""
	@echo "=== C# tests (dotnet test) ==="
	@dotnet test rijndael-csharp/RijndaelTests/RijndaelTests.csproj --nologo
	@echo ""
	@echo "=== Groovy tests ==="
	@groovy rijndael-groovy/RijndaelTest.groovy
	@echo ""
	@echo "=== Integration tests (all implementations) ==="
	@sh tests/test_integration.sh

clean:
	@rm -rf *.exe *.class *.jar dotnet-build
	@rm -rf rijndael-rust/target
	@rm -rf rijndael-haskell/.stack-work
	@rm -f plain*.txt output*.txt.rij *.rij.sig
	@rm -f test_rijndael_c
	@rm -f rijndael-java/RijndaelTest.class
