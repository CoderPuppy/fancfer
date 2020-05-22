module Fancfer.W1 where

import RIO
import qualified Data.ByteString as BS
import qualified Data.Map as M
import qualified Data.Text as T
import qualified System.Posix as Posix

newtype Id = Id T.Text deriving (Show)

data DirEntry = DirEntry {
	id :: Id,
	mode :: Posix.FileMode
} deriving (Show)

data Commit = Commit {
	root :: Id,
	message :: T.Text,
	parents :: [Id]
} deriving (Show)

data Repository = Repository {
} deriving (Show)

data Object
	= ODirectory (M.Map T.Text DirEntry)
	| OBlob BS.ByteString
	| OCommit Commit
	| ORepository Repository
	deriving (Show)

-- TODO: renaming

-- uses for externalizing state:
-- - changes in working directory
-- - missing files (git annex, partial checkouts)
