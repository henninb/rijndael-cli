module Main where

import Data.Bits (xor)
import qualified Data.ByteString as BS
import System.Directory (doesFileExist, getFileSize, removeFile)
import System.Exit (ExitCode (..))
import System.IO.Temp (withSystemTempDirectory)
import System.Process (readProcessWithExitCode)
import Test.Hspec

-- ---------------------------------------------------------------------------
-- Constants
-- ---------------------------------------------------------------------------

keyHex, ivHex, wrongKeyHex, wrongIVHex :: String
keyHex      = "594193e330c8e8312f244c9cff045b73e66c301c30eb3bf0ec943a25e7a45650"
ivHex       = "2cef85f5259ae311034de17fda3b8369"
wrongKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"
wrongIVHex  = "ffffffffffffffffffffffffffffffff"

plaintext :: String
plaintext = "my message to you, let's win"  -- 28 bytes

-- ---------------------------------------------------------------------------
-- Helpers: run binaries via `stack exec`
-- ---------------------------------------------------------------------------

-- Run the encrypt binary via `stack exec rijndael-encrypt`
runEncrypt :: FilePath  -- temp dir
           -> String    -- plaintext
           -> String    -- key hex  (empty = default)
           -> String    -- iv hex   (empty = default)
           -> IO (ExitCode, String, String)
runEncrypt dir pt kHex ivH = do
  let inputFile  = dir ++ "/input.txt"
      outputFile = dir ++ "/output.rij"
      keyFile    = dir ++ "/input.key"
      ivFile     = dir ++ "/input.iv"
  writeFile inputFile pt
  writeFile keyFile  (if null kHex then keyHex else kHex)
  writeFile ivFile   (if null ivH  then ivHex  else ivH)
  readProcessWithExitCode "stack"
    ["exec", "--", "rijndael-encrypt", inputFile, outputFile, keyFile, ivFile] ""

-- Run the decrypt binary via `stack exec rijndael-decrypt`
runDecrypt :: FilePath  -- temp dir
           -> String    -- key hex (empty = default)
           -> String    -- iv hex  (empty = default)
           -> IO (ExitCode, String, String)
runDecrypt dir kHex ivH = do
  let ctFile  = dir ++ "/output.rij"
      outFile = dir ++ "/decrypted.txt"
      keyFile = dir ++ "/dec.key"
      ivFile  = dir ++ "/dec.iv"
  writeFile keyFile (if null kHex then keyHex else kHex)
  writeFile ivFile  (if null ivH  then ivHex  else ivH)
  readProcessWithExitCode "stack"
    ["exec", "--", "rijndael-decrypt", ctFile, outFile, keyFile, ivFile] ""

-- ---------------------------------------------------------------------------
-- Main
-- ---------------------------------------------------------------------------

main :: IO ()
main = hspec $ do

  -- -------------------------------------------------------------------------
  -- Encrypt – output structure
  -- -------------------------------------------------------------------------
  describe "rijndael-encrypt" $ do
    describe "output structure" $ do
      it "creates the ciphertext file" $
        withSystemTempDirectory "rijndael-enc-test" $ \dir -> do
          (ec, _, _) <- runEncrypt dir plaintext "" ""
          ec `shouldBe` ExitSuccess
          doesFileExist (dir ++ "/output.rij") >>= (`shouldBe` True)

      it "creates the .sig file" $
        withSystemTempDirectory "rijndael-enc-test" $ \dir -> do
          (ec, _, _) <- runEncrypt dir plaintext "" ""
          ec `shouldBe` ExitSuccess
          doesFileExist (dir ++ "/output.rij.sig") >>= (`shouldBe` True)

      it "ciphertext length is a multiple of 16" $
        withSystemTempDirectory "rijndael-enc-test" $ \dir -> do
          (ec, _, _) <- runEncrypt dir plaintext "" ""
          ec `shouldBe` ExitSuccess
          sz <- getFileSize (dir ++ "/output.rij")
          (sz `mod` 16) `shouldBe` 0

      it ".sig file is 64 bytes (HMAC-SHA512)" $
        withSystemTempDirectory "rijndael-enc-test" $ \dir -> do
          (ec, _, _) <- runEncrypt dir plaintext "" ""
          ec `shouldBe` ExitSuccess
          sz <- getFileSize (dir ++ "/output.rij.sig")
          sz `shouldBe` 64

    -- -----------------------------------------------------------------------
    -- Encrypt – PKCS7 padding
    -- -----------------------------------------------------------------------
    describe "PKCS7 padding" $ do
      let paddingCases =
            [ (0,  16, "empty input -> one full padding block")
            , (1,  16, "1-byte input -> padded to 16")
            , (15, 16, "15-byte input -> padded to 16")
            , (16, 32, "16-byte input (full block) -> extra block appended")
            , (17, 32, "17-byte input -> padded to 32")
            , (28, 32, "28-byte input (test vector) -> padded to 32")
            , (31, 32, "31-byte input -> padded to 32")
            , (32, 48, "32-byte input -> extra block appended")
            ]
      mapM_
        ( \(inputLen, expectedLen, label) ->
            it label $
              withSystemTempDirectory "rijndael-pad-test" $ \dir -> do
                (ec, _, _) <- runEncrypt dir (replicate inputLen 'A') "" ""
                ec `shouldBe` ExitSuccess
                sz <- getFileSize (dir ++ "/output.rij")
                fromIntegral sz `shouldBe` (expectedLen :: Int)
        )
        paddingCases

    -- -----------------------------------------------------------------------
    -- Encrypt – determinism
    -- -----------------------------------------------------------------------
    describe "determinism" $ do
      it "same key/IV produces same ciphertext" $
        withSystemTempDirectory "rijndael-det-test" $ \dir1 ->
          withSystemTempDirectory "rijndael-det-test" $ \dir2 -> do
            (ec1, _, _) <- runEncrypt dir1 plaintext "" ""
            (ec2, _, _) <- runEncrypt dir2 plaintext "" ""
            ec1 `shouldBe` ExitSuccess
            ec2 `shouldBe` ExitSuccess
            ct1 <- BS.readFile (dir1 ++ "/output.rij")
            ct2 <- BS.readFile (dir2 ++ "/output.rij")
            ct1 `shouldBe` ct2

      it "different IV produces different ciphertext" $
        withSystemTempDirectory "rijndael-iv-test" $ \dir1 ->
          withSystemTempDirectory "rijndael-iv-test" $ \dir2 -> do
            runEncrypt dir1 plaintext "" ""
            runEncrypt dir2 plaintext "" wrongIVHex
            ct1 <- BS.readFile (dir1 ++ "/output.rij")
            ct2 <- BS.readFile (dir2 ++ "/output.rij")
            ct1 `shouldNotBe` ct2

      it "different key produces different ciphertext" $
        withSystemTempDirectory "rijndael-key-test" $ \dir1 ->
          withSystemTempDirectory "rijndael-key-test" $ \dir2 -> do
            runEncrypt dir1 plaintext "" ""
            runEncrypt dir2 plaintext wrongKeyHex ""
            ct1 <- BS.readFile (dir1 ++ "/output.rij")
            ct2 <- BS.readFile (dir2 ++ "/output.rij")
            ct1 `shouldNotBe` ct2

    -- -----------------------------------------------------------------------
    -- Encrypt – stdout messages
    -- -----------------------------------------------------------------------
    describe "stdout messages" $ do
      it "contains language label" $
        withSystemTempDirectory "rijndael-out-test" $ \dir -> do
          (ec, out, _) <- runEncrypt dir plaintext "" ""
          ec `shouldBe` ExitSuccess
          out `shouldContain` "[ Haskell | encrypt ]"

      it "contains algorithm name" $
        withSystemTempDirectory "rijndael-out-test" $ \dir -> do
          (ec, out, _) <- runEncrypt dir plaintext "" ""
          ec `shouldBe` ExitSuccess
          out `shouldContain` "AES-256/CBC/PKCS7"

    -- -----------------------------------------------------------------------
    -- Encrypt – error handling
    -- -----------------------------------------------------------------------
    describe "error handling" $ do
      it "exits 1 on no arguments" $ do
        (ec, _, _) <- readProcessWithExitCode "stack" ["exec", "--", "rijndael-encrypt"] ""
        ec `shouldBe` ExitFailure 1

      it "exits 1 on too few arguments" $ do
        (ec, _, _) <- readProcessWithExitCode "stack"
          ["exec", "--", "rijndael-encrypt", "a", "b"] ""
        ec `shouldBe` ExitFailure 1

      it "exits non-zero on missing input file" $
        withSystemTempDirectory "rijndael-err-test" $ \dir -> do
          writeFile (dir ++ "/input.key") keyHex
          writeFile (dir ++ "/input.iv")  ivHex
          (ec, _, _) <- readProcessWithExitCode "stack"
            [ "exec", "--", "rijndael-encrypt"
            , dir ++ "/nonexistent.txt"
            , dir ++ "/output.rij"
            , dir ++ "/input.key"
            , dir ++ "/input.iv" ] ""
          ec `shouldNotBe` ExitSuccess

  -- -------------------------------------------------------------------------
  -- Decrypt – roundtrip
  -- -------------------------------------------------------------------------
  describe "rijndael-decrypt" $ do
    describe "roundtrip" $ do
      it "recovers the original plaintext" $
        withSystemTempDirectory "rijndael-rt-test" $ \dir -> do
          (ec1, _, _) <- runEncrypt dir plaintext "" ""
          ec1 `shouldBe` ExitSuccess
          (ec2, _, _) <- runDecrypt dir "" ""
          ec2 `shouldBe` ExitSuccess
          got <- readFile (dir ++ "/decrypted.txt")
          got `shouldBe` plaintext

      it "roundtrip with empty input" $
        withSystemTempDirectory "rijndael-rt-empty" $ \dir -> do
          runEncrypt dir "" "" ""
          (ec, _, _) <- runDecrypt dir "" ""
          ec `shouldBe` ExitSuccess
          got <- BS.readFile (dir ++ "/decrypted.txt")
          BS.length got `shouldBe` 0

      it "roundtrip with exactly one block of input" $
        withSystemTempDirectory "rijndael-rt-block" $ \dir -> do
          let pt = "1234567890abcdef"  -- 16 bytes
          runEncrypt dir pt "" ""
          (ec, _, _) <- runDecrypt dir "" ""
          ec `shouldBe` ExitSuccess
          got <- readFile (dir ++ "/decrypted.txt")
          got `shouldBe` pt

    -- -----------------------------------------------------------------------
    -- Decrypt – MAC verification
    -- -----------------------------------------------------------------------
    describe "MAC verification" $ do
      it "stdout contains 'verified OK'" $
        withSystemTempDirectory "rijndael-mac-test" $ \dir -> do
          runEncrypt dir plaintext "" ""
          (ec, out, _) <- runDecrypt dir "" ""
          ec `shouldBe` ExitSuccess
          out `shouldContain` "verified OK"

      it "fails on tampered ciphertext" $
        withSystemTempDirectory "rijndael-mac-tamper" $ \dir -> do
          runEncrypt dir plaintext "" ""
          let ctFile = dir ++ "/output.rij"
          ct <- BS.readFile ctFile
          let tampered = BS.cons (BS.head ct `xor` 0xFF) (BS.tail ct)
          BS.writeFile ctFile tampered
          (ec, _, _) <- runDecrypt dir "" ""
          ec `shouldNotBe` ExitSuccess

      it "fails on tampered .sig" $
        withSystemTempDirectory "rijndael-sig-tamper" $ \dir -> do
          runEncrypt dir plaintext "" ""
          let sigFile = dir ++ "/output.rij.sig"
          sig <- BS.readFile sigFile
          let tampered = BS.cons (BS.head sig `xor` 0xFF) (BS.tail sig)
          BS.writeFile sigFile tampered
          (ec, _, _) <- runDecrypt dir "" ""
          ec `shouldNotBe` ExitSuccess

      it "issues WARNING when .sig is missing" $
        withSystemTempDirectory "rijndael-nosig-test" $ \dir -> do
          runEncrypt dir plaintext "" ""
          removeFile (dir ++ "/output.rij.sig")
          (ec, out, _) <- runDecrypt dir "" ""
          ec `shouldBe` ExitSuccess
          out `shouldContain` "WARNING"

      it "fails when wrong key is used" $
        withSystemTempDirectory "rijndael-wrongkey-test" $ \dir -> do
          runEncrypt dir plaintext "" ""
          (ec, _, _) <- runDecrypt dir wrongKeyHex ""
          ec `shouldNotBe` ExitSuccess

    -- -----------------------------------------------------------------------
    -- Decrypt – error handling
    -- -----------------------------------------------------------------------
    describe "error handling" $ do
      it "exits 1 on no arguments" $ do
        (ec, _, _) <- readProcessWithExitCode "stack" ["exec", "--", "rijndael-decrypt"] ""
        ec `shouldBe` ExitFailure 1

      it "exits non-zero on missing ciphertext file" $
        withSystemTempDirectory "rijndael-err-dec" $ \dir -> do
          writeFile (dir ++ "/input.key") keyHex
          writeFile (dir ++ "/input.iv")  ivHex
          (ec, _, _) <- readProcessWithExitCode "stack"
            [ "exec", "--", "rijndael-decrypt"
            , dir ++ "/nonexistent.rij"
            , dir ++ "/out.txt"
            , dir ++ "/input.key"
            , dir ++ "/input.iv" ] ""
          ec `shouldNotBe` ExitSuccess
