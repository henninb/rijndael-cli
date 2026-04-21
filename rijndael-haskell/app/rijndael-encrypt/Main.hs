module Main where

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (Cipher (..), IV, cbcEncrypt, makeIV)
import Crypto.Error (CryptoFailable (..))
import Crypto.Hash (SHA512)
import Crypto.MAC.HMAC (HMAC, hmac)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import System.Environment (getArgs)
import System.Exit (ExitCode (..), exitWith)
import System.IO (hPutStrLn, stderr)

die :: String -> IO a
die msg = hPutStrLn stderr msg >> exitWith (ExitFailure 1)

readHexFile :: FilePath -> Int -> String -> IO BS.ByteString
readHexFile path expectedLen label = do
  raw <- BS.readFile path
  let stripped = BS.filter (\b -> b /= 10 && b /= 13) raw
  case B16.decode stripped of
    Right bs
      | BS.length bs == expectedLen -> return bs
      | otherwise ->
          die $ "ABORT: " ++ label ++ " wrong length: expected "
            ++ show expectedLen ++ " bytes, got " ++ show (BS.length bs)
    Left err -> die $ "ABORT: invalid " ++ label ++ " hex: " ++ err

pkcs7Pad :: Int -> BS.ByteString -> BS.ByteString
pkcs7Pad blockSize bs =
  let padLen = blockSize - (BS.length bs `mod` blockSize)
  in bs <> BS.replicate padLen (fromIntegral padLen)

main :: IO ()
main = do
  args <- getArgs
  case args of
    [ifname, ofname, keyfname, ivfname] -> do
      putStrLn "[ Haskell | encrypt ] algorithm  : AES-256/CBC/PKCS7"
      keyBytes  <- readHexFile keyfname 32 "key"
      ivBytes   <- readHexFile ivfname  16 "iv"
      plaintext <- BS.readFile ifname
      let padded = pkcs7Pad 16 plaintext
      putStrLn $ "[ Haskell | encrypt ] input      : " ++ show (BS.length plaintext)
               ++ " bytes  ->  padded : " ++ show (BS.length padded) ++ " bytes"
      aes <- case cipherInit keyBytes of
        CryptoPassed a -> return (a :: AES256)
        CryptoFailed e -> die $ "ABORT: cipherInit: " ++ show e
      iv <- case makeIV ivBytes of
        Just i  -> return (i :: IV AES256)
        Nothing -> die "ABORT: makeIV failed"
      let ciphertext = cbcEncrypt aes iv padded :: BS.ByteString
      BS.writeFile ofname ciphertext
      putStrLn $ "[ Haskell | encrypt ] output     : " ++ ofname
      let sig = BA.convert (hmac keyBytes ciphertext :: HMAC SHA512) :: BS.ByteString
      BS.writeFile (ofname ++ ".sig") sig
      putStrLn "[ Haskell | encrypt ] signature  : written"
    _ -> do
      hPutStrLn stderr "Usage: rijndael-encrypt <ifname> <ofname> <keyfname> <ivfname>"
      exitWith (ExitFailure 1)
