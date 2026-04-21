module Main where

import Crypto.Cipher.AES (AES256)
import Crypto.Cipher.Types (Cipher (..), IV, cbcDecrypt, makeIV)
import Crypto.Error (CryptoFailable (..))
import Crypto.Hash (SHA512)
import Crypto.MAC.HMAC (HMAC, hmac)
import qualified Data.ByteArray as BA
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import System.Directory (doesFileExist)
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

pkcs7Unpad :: BS.ByteString -> Either String BS.ByteString
pkcs7Unpad bs
  | BS.null bs               = Left "empty plaintext"
  | padLen < 1 || padLen > 16 = Left "invalid padding byte"
  | otherwise                = Right $ BS.take (BS.length bs - padLen) bs
  where padLen = fromIntegral (BS.last bs)

main :: IO ()
main = do
  args <- getArgs
  case args of
    [ifname, ofname, keyfname, ivfname] -> do
      putStrLn "[ Haskell | decrypt ] algorithm  : AES-256/CBC/PKCS7"
      keyBytes   <- readHexFile keyfname 32 "key"
      ivBytes    <- readHexFile ivfname  16 "iv"
      ciphertext <- BS.readFile ifname
      putStrLn $ "[ Haskell | decrypt ] input      : " ++ show (BS.length ciphertext) ++ " bytes"
      if BS.length ciphertext `mod` 16 /= 0
        then die "ABORT: ciphertext length is not a multiple of block size"
        else return ()
      sigExists <- doesFileExist (ifname ++ ".sig")
      if sigExists
        then do
          storedSig <- BS.readFile (ifname ++ ".sig")
          let computedSig = BA.convert (hmac keyBytes ciphertext :: HMAC SHA512) :: BS.ByteString
          if BA.constEq storedSig computedSig
            then putStrLn "[ Haskell | decrypt ] MAC        : verified OK"
            else die "ABORT: MAC verification failed"
        else putStrLn "[ Haskell | decrypt ] WARNING    : no .sig file — skipping MAC verification"
      aes <- case cipherInit keyBytes of
        CryptoPassed a -> return (a :: AES256)
        CryptoFailed e -> die $ "ABORT: cipherInit: " ++ show e
      iv <- case makeIV ivBytes of
        Just i  -> return (i :: IV AES256)
        Nothing -> die "ABORT: makeIV failed"
      let padded = cbcDecrypt aes iv ciphertext :: BS.ByteString
      plaintext <- case pkcs7Unpad padded of
        Right pt  -> return pt
        Left  err -> die $ "ABORT: PKCS7 unpad: " ++ err
      BS.writeFile ofname plaintext
      putStrLn $ "[ Haskell | decrypt ] output     : " ++ ofname
    _ -> do
      hPutStrLn stderr "Usage: rijndael-decrypt <ifname> <ofname> <keyfname> <ivfname>"
      exitWith (ExitFailure 1)
