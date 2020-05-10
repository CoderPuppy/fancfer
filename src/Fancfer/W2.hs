module Fancfer.W2 where

import qualified Data.Text as T
import qualified Data.Map as M
import qualified System.Posix as Posix
import qualified Data.ByteString as BS

-- let repo <- Repo in repo/HEAD

-- data Expr
-- 	= Union [Expr]
-- 	| Directory (M.Map Expr Expr)
-- 	| Text T.Text
-- 	| Blob BS.ByteString
-- 	| 

data FF a
instance Functor FF
instance Applicative FF
instance Monad FF
data EmFn = EmFn String ([Value] -> FF (Either Source Value))
instance Show EmFn where
	show (EmFn name _) = name
data DirEntry a = DirEntry {
	mode :: Posix.FileMode,
	value :: a
} deriving (Show, Functor)
data Value'
	= VFn EmFn
	| VText T.Text
	| VBlob BS.ByteString
  | VSymlink T.Text
	| VDir (M.Map T.Text (DirEntry Value))
	deriving (Show)
data Source
  = SAp Value [Value]
  deriving (Show)
data Value = Value [Source] Value' deriving (Show)

expandSource :: Source -> FF (Either Source Value)
expandSource (SAp (Value _ (VFn (EmFn _ fn))) args) = fn args

fullyExpandSource :: Source -> FF Value
fullyExpandSource s = fmap (\(Value srcs v) -> Value (s:srcs) v) $ expandSource s >>= either fullyExpandSource pure

sourceInfo :: Source -> Value
sourceInfo (SAp fn args) = Value [] $ VDir $ M.fromList [
    ("type", DirEntry Posix.stdFileMode $ Value [] $ VText "ap"),
    ("fn", DirEntry Posix.stdFileMode $ reify fn),
    ("args", DirEntry Posix.stdFileMode $ Value [] $ VDir $
      M.fromList $ zipWith (,) (fmap (T.pack . show) [1..]) $
      fmap (DirEntry Posix.stdFileMode . reify) args)
  ]

sourcesInfo :: [Source] -> Value
sourcesInfo [src] = sourceInfo src

reify' :: Value' -> Value
reify' (VFn fn) = Value [] $ VFn fn
reify' (VText txt) = Value [] $ VText txt
reify' (VBlob bs) = Value [] $ VBlob bs
reify' (VSymlink to) = Value [] $ VSymlink to
reify' (VDir entries) = Value [] $ VDir $ fmap (fmap reify) entries

reify :: Value -> Value
reify (Value [] v) = reify' v
reify (Value srcs (VDir entries)) = Value [] $ VDir $
  M.insert ".fancfer" (DirEntry Posix.stdFileMode $ sourcesInfo srcs) $
  fmap (fmap reify) entries
reify (Value srcs v) = Value [] $ VDir $ M.fromList [
    (".fancfer", DirEntry Posix.stdFileMode $ sourcesInfo srcs),
    ("value", DirEntry Posix.stdFileMode $ reify' v)
  ]
