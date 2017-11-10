module Main where

import Control.Monad         ((<=<), foldM, join, liftM, liftM2, replicateM, zipWithM)
import Data.ByteString.Char8 (ByteString, pack)
import Data.IntMap.Strict    (empty, insert, toList)
import System.Exit           (ExitCode(..), exitWith)
import System.Random.Shuffle (shuffleM)
import Test.HUnit            (Counts(..), Test(..), assertEqual, runTestTT)
import Test.QuickCheck       (Arbitrary(..), sample')

import Crypto.BLS

instance Arbitrary ByteString where
  arbitrary = pack <$> arbitrary

testSignVerify :: ByteString -> ByteString -> IO Test
testSignVerify seed message = do
  secretKey <- deriveSecretKey seed
  publicKey <- derivePublicKey secretKey
  signature <- sign secretKey message
  success <- verifySig signature message publicKey
  pure . TestCase $ assertEqual debug True success
  where debug = concat ["\nTest: SignVerify\nSeed: ", show seed, "\nMessage: ", show message]

testProveVerify :: ByteString -> IO Test
testProveVerify seed = do
  secretKey <- deriveSecretKey seed
  publicKey <- derivePublicKey secretKey
  pop <- prove secretKey
  success <- verifyPop pop publicKey
  pure . TestCase $ assertEqual debug True success
  where debug = concat ["\nTest: ProveVerify\nSeed: ", show seed]

testShamir :: ByteString -> IO Test
testShamir message = do
  Group {..} <- shamir 201 400
  participants <- shuffleM $ toList groupMembers
  shares <- foldM step empty participants
  signture <- recover shares
  success <- verifySig signture message groupPublicKey
  pure . TestCase $ assertEqual debug True success
  where debug = concat ["\nTest: Shamir\nMessage: ", show message]
        step accum (i, (_, secretKey)) = do
          signature <- sign secretKey message
          pure $ insert i signature accum

random :: IO [ByteString]
random = sample' arbitrary

tests :: IO [[Test]]
tests = sequence $ map join
  [
    liftM (mapM testShamir) random,
    liftM (mapM testProveVerify) random,
    liftM2 (zipWithM testSignVerify) random random
  ]

main :: IO ()
main = do
  initialize
  Counts {..} <- runTestTT . TestList <=< replicateM 1000 $ TestList . concat <$> tests
  exitWith $ case failures + errors of
    0 -> ExitSuccess
    _ -> ExitFailure 1
