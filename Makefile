LIBS=-Llib

all: linux

linux:
	@rm -rf *.exe
	@gcc rijndael-c/rijndael-alg-fst.c rijndael-c/rijndael-api-fst.c rijndael-c/rijndael-encrypt.c -o rijndael-encrypt.exe -Irijndael-c $(LIBS) -O2 -Wall -lssl -lcrypto
	@gcc rijndael-c/rijndael-alg-fst.c rijndael-c/rijndael-api-fst.c rijndael-c/rijndael-decrypt.c -o rijndael-decrypt.exe -Irijndael-c $(LIBS) -O2 -Wall -lssl -lcrypto
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

clean:
	@rm -rf *.exe *.class *.jar dotnet-build
	@rm -rf rijndael-rust/target
	@rm -rf rijndael-haskell/.stack-work
	@rm -f plain*.txt output*.txt.rij *.rij.sig
