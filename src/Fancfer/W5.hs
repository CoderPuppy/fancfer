module Fancfer.W5 where

import RIO
import Data.Binary
import Data.Digest.Pure.SHA
import Data.Proxy
import GHC.Generics
import GHC.OverloadedLabels
import System.Posix
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Lazy as BSL
import qualified Data.Map as M
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Control.Monad.IO.Class
import Control.Lens hiding (over)
import Data.Profunctor
import UnliftIO.Directory

deriving instance Generic CMode
instance Binary CMode

class HashAlgo h where
	hash :: Proxy h -> BSL.ByteString -> BSL.ByteString
instance HashAlgo SHA256State where
	hash _ = bytestringDigest . sha256

data Id h = Id BS.ByteString deriving (Show, Generic, Binary)
data Object h
	= OBlob BSL.ByteString
	| ODir (M.Map T.Text (Id h))
	| OSourced (Source h)
	| OFakeReal (Id h)
	deriving (Show, Generic, Binary)
-- TODO: symlinks, lists
data Source h = Source {
	_type :: SourceType,
	arg :: Id h
} deriving (Show, Generic, Binary)
data SourceType = STAutoCommit deriving (Show, Generic, Binary)

objId :: forall h. HashAlgo h => Object h -> Id h
objId = Id . BSL.toStrict . hash (Proxy @h) . encode

data IObject h = IObject {
	id :: Id h,
	obj :: Object h
}

data From h real
	= FRoot (From h real)
	| FDir (RDir h real) T.Text
	| FSourceArg (RSource h real)
	| FSourceVal (RSource h real)
data Ref h real where
	RObj :: Id h -> From h real -> Ref h False
	RReal :: From h True -> Ref h True
newtype RDir h real = RDir (Ref h real)
newtype RSource h real = RSource (Ref h real)
