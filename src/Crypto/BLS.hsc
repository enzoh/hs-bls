module Crypto.BLS
  ( SecretKey(..)
  , PublicKey(..)
  , Signature(..)
  , Group(..)
  , initialize
  , deriveSecretKey
  , derivePublicKey
  , sign
  , verifySig
  , prove
  , verifyPop
  , shamir
  , recover
  ) where

import Control.Monad          (foldM, void)
import Data.Binary            (Binary)
import Data.ByteString.Char8  (ByteString)
import Data.ByteString.Unsafe (unsafePackCStringFinalizer, unsafeUseAsCStringLen)
import Data.IntMap.Strict     (IntMap, empty, insert, size, traverseWithKey)
import Data.String            (IsString)
import Data.Void              (Void)
import Data.Word              (Word8)
import Foreign.C.String       (CString)
import Foreign.Marshal.Alloc  (free)
import Foreign.Ptr            (FunPtr, Ptr, castPtr, plusPtr)
import Foreign.Storable       (peek)
import GHC.Generics           (Generic)

#include <bindings.dsl.h>

#ccall shimInit, IO ()
#ccall shimSign, CString -> Int -> CString -> Int -> IO CString
#ccall shimVerify, CString -> Int -> CString -> Int -> CString -> Int -> IO Int
#ccall fromSecretNew, CString -> Int -> IO CString
#ccall getPopNew, CString -> Int -> IO CString
#ccall shimVerifyPop, CString -> Int -> CString -> Int -> IO Int
#ccall frmapnew, CString -> Int -> IO CString
#ccall dkgNew, Int -> IO (Ptr Void)
#ccall dkgFree, Ptr Void -> IO ()
#ccall dkgSecretShareNew, Ptr Void -> Int -> IO CString
#ccall dkgGroupPublicKeyNew, Ptr Void -> IO CString
#ccall signatureShareNew, Int -> IO (Ptr Void)
#ccall signatureShareFree, Ptr Void -> IO ()
#ccall signatureShareAdd, Ptr Void -> Int -> CString -> Int -> IO ()
#ccall recoverSignatureNew, Ptr Void -> IO CString

newtype PublicKey = PublicKey { getPublicKey :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Read, Show)

newtype SecretKey = SecretKey { getSecretKey :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Read, Show)

newtype Signature = Signature { getSignature :: ByteString }
  deriving (Eq, Generic, IsString, Ord, Read, Show)

data Group =
  Group
  { groupMembers   :: IntMap (PublicKey, SecretKey)
  , groupPublicKey :: PublicKey
  , groupThreshold :: Int
  } deriving (Eq, Generic, Ord, Read, Show)

instance Binary Group
instance Binary PublicKey
instance Binary SecretKey
instance Binary Signature

extract :: CString -> IO ByteString
extract str = peek ptr >>= \ len ->
  unsafePackCStringFinalizer (plusPtr ptr 1) (fromIntegral len) (free ptr)
  where ptr = castPtr str :: Ptr Word8

-- |
-- Initialize a BLS cryptosystem.
initialize :: IO ()
initialize = c'shimInit

-- |
-- Derive a BLS secret key from a random seed.
deriveSecretKey :: ByteString -> IO SecretKey
deriveSecretKey xxx =
  unsafeUseAsCStringLen xxx $ \ xxxPtr -> do
    result <- uncurry c'frmapnew xxxPtr
    SecretKey <$> extract result

-- |
-- Derive a BLS public key from a BLS secret key.
derivePublicKey :: SecretKey -> IO PublicKey
derivePublicKey (SecretKey sec) =
  unsafeUseAsCStringLen sec $ \ secPtr -> do
    result <- uncurry c'fromSecretNew secPtr
    PublicKey <$> extract result

-- |
-- Sign a message using a BLS secret key.
sign :: SecretKey -> ByteString -> IO Signature
sign (SecretKey sec) msg =
  unsafeUseAsCStringLen sec $ \ secPtr ->
    unsafeUseAsCStringLen msg $ \ msgPtr -> do
      result <- uncurry (uncurry c'shimSign secPtr) msgPtr
      Signature <$> extract result

-- |
-- Verify a BLS signature on a message using a BLS public key.
verifySig :: Signature -> ByteString -> PublicKey -> IO Bool
verifySig (Signature sig) msg (PublicKey pub) =
  unsafeUseAsCStringLen sig $ \ sigPtr ->
    unsafeUseAsCStringLen msg $ \ msgPtr ->
      unsafeUseAsCStringLen pub $ \ pubPtr -> do
        result <- uncurry (uncurry (uncurry c'shimVerify sigPtr) pubPtr) msgPtr
        pure $ result > 0

-- |
-- Prove possession of a BLS secret key.
prove :: SecretKey -> IO ByteString
prove (SecretKey sec) =
  unsafeUseAsCStringLen sec $ \ secPtr -> do
    result <- uncurry c'getPopNew secPtr
    extract result

-- |
-- Verify a proof of possession using a BLS public key.
verifyPop :: ByteString -> PublicKey -> IO Bool
verifyPop pop (PublicKey pub) =
  unsafeUseAsCStringLen pop $ \ popPtr ->
    unsafeUseAsCStringLen pub $ \ pubPtr -> do
      result <- uncurry (uncurry c'shimVerifyPop popPtr) pubPtr
      pure $ result > 0

-- |
-- Divide a BLS secret key into 'n' shares such that 't' shares can combine to
-- produce a valid signature.
shamir
  :: Int -- ^ 't'
  -> Int -- ^ 'n'
  -> IO Group
shamir t n = do
  ptr <- c'dkgNew t
  members <- foldM (step ptr) empty [1..n]
  result <- c'dkgGroupPublicKeyNew ptr
  publicKey <- PublicKey <$> extract result
  c'dkgFree ptr
  pure $ Group members publicKey t
  where
  step ptr acc i = do
    result <- c'dkgSecretShareNew ptr i
    secretKey <- SecretKey <$> extract result
    publicKey <- derivePublicKey secretKey
    pure $ insert i (publicKey, secretKey) acc

-- |
-- Recover a BLS signature from a threshold of BLS signature shares.
recover :: IntMap Signature -> IO Signature
recover sigs = do
  ptr <- c'signatureShareNew $ size sigs
  void $ flip traverseWithKey sigs $ \ i (Signature sig) ->
    unsafeUseAsCStringLen sig $ \ sigPtr ->
      uncurry (c'signatureShareAdd ptr i) sigPtr
  result <- c'recoverSignatureNew ptr
  c'signatureShareFree ptr
  Signature <$> extract result
