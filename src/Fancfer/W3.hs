module Fancfer.W3 where

import Control.Arrow
import Control.Lens hiding (_Just)
import Control.Lens.TH (makePrisms)
import Data.Bool
import Data.Fix
import Data.Foldable
import Data.Maybe
import Data.Profunctor
import Data.Tuple
import GHC.OverloadedLabels
import Text.Read
import qualified Data.Map as M
import qualified Data.Text as T
import Control.Monad.Trans.Writer.Lazy
import Data.Monoid

class Functor f => Pure f where
	pure' :: a -> f a
	default pure' :: Applicative f => a -> f a
	pure' = pure
instance (Functor f, Applicative f) => Pure f

_Just :: (Choice p, Pure f) => p a (f b) -> p (Maybe a) (f (Maybe b))
_Just = dimap (\case {
		Just a -> Left a;
		Nothing -> Right ()
	}) (either (fmap Just) (const $ pure' Nothing)) . left'
type Fix' f = f (Fix f)
_Fix :: (Profunctor p, Functor f) => p (Fix' a) (f (Fix' b)) -> p (Fix a) (f (Fix b))
_Fix = dimap unFix (fmap Fix)

data Value sv
	= VText T.Text
	| VDir (M.Map T.Text (Value sv))
	| VSourced (Source sv)
	| VCommit (Commit sv) | VNoCommit -- TODO
	| VBackRefCycle -- TODO
	| VFakeReal (Value sv)
	deriving (Show)
_VDir :: (Choice p, Pure f) => p (M.Map T.Text (Value sv)) (f (M.Map T.Text (Value sv))) -> p (Value sv) (f (Value sv))
_VDir = dimap (\case { VDir a -> Left a; v -> Right v }) (either (fmap VDir) pure') . left'
_VText :: (Choice p, Pure f) => p T.Text (f T.Text) -> p (Value sv) (f (Value sv))
_VText = dimap (\case { VText a -> Left a; v -> Right v }) (either (fmap VText) pure') . left'

data SourceType = STCommitLog | STBackRef | STDescend | STAutoCommit deriving (Show)
-- STRepo, STBackRef, STCommitLog, STDescend, STAutoCommit
data Source sv = Source {
	_type :: SourceType,
	arg :: Value sv,
	val :: sv
} deriving (Show)
instance (Strong p, Functor f) => IsLabel "type" (p SourceType (f SourceType) -> p (Source sv) (f (Source sv))) where
	fromLabel = dimap (\c@(Source {_type}) -> (_type, c)) (\(_type, c) -> fmap (\_type -> c {_type}) _type) . first'
instance (Strong p, Functor f) => IsLabel "arg" (p (Value sv) (f (Value sv)) -> p (Source sv) (f (Source sv))) where
	fromLabel = dimap (\c@(Source {arg}) -> (arg, c)) (\(arg, c) -> fmap (\arg -> c {arg}) arg) . first'
instance (Strong p, Functor f) => IsLabel "val" (p sv (f sv) -> p (Source sv) (f (Source sv))) where
	fromLabel = dimap (\c@(Source {val}) -> (val, c)) (\(val, c) -> fmap (\val -> c {val}) val) . first'

data Commit sv = Commit {
	value :: Value sv,
	message :: T.Text,
	parents :: [Value sv]
} deriving (Show)
instance (Strong p, Functor f) => IsLabel "value" (p (Value sv) (f (Value sv)) -> p (Commit sv) (f (Commit sv))) where
	fromLabel = dimap (\c@(Commit {value}) -> (value, c)) (\(value, c) -> fmap (\value -> c {value}) value) . first'
instance (Strong p, Functor f) => IsLabel "message" (p T.Text (f T.Text) -> p (Commit sv) (f (Commit sv))) where
	fromLabel = dimap (\c@(Commit {message}) -> (message, c)) (\(message, c) -> fmap (\message -> c {message}) message) . first'
instance (Strong p, Functor f) => IsLabel "parents" (p [Value sv] (f [Value sv]) -> p (Commit sv) (f (Commit sv))) where
	fromLabel = dimap (\c@(Commit {parents}) -> (parents, c)) (\(parents, c) -> fmap (\parents -> c {parents}) parents) . first'

data PathPart = PPDir T.Text | PPSrcArg | PPSrcVal deriving (Show, Read)
type Path = [PathPart]

pathBackRef :: Path -> (Int, Int) -> Maybe Path
pathBackRef path (0, 0) = Just path
pathBackRef [] _ = Nothing
pathBackRef (PPSrcVal:path) (0, nSrc) = pathBackRef path (0, nSrc - 1)
pathBackRef (PPSrcVal:path) (nReal, nSrc) = pathBackRef path (nReal, nSrc)
pathBackRef (PPSrcArg:path) (nReal, nSrc) = pathBackRef path (nReal - 1, nSrc)
pathBackRef (PPDir name:path) (nReal, nSrc) = pathBackRef path (nReal - 1, nSrc)

data DepsTree
	= DTRel | DTIrrel
	| DTDir (T.Text -> DepsTree)
	| DTSourced DepsTree DepsTree
instance Semigroup DepsTree where
	DTRel <> _ = DTRel
	_ <> DTRel = DTRel
	DTIrrel <> dt = dt
	dt <> DTIrrel = dt
	DTDir a <> DTDir b = DTDir $ (<>) <$> a <*> b
	DTSourced aArg aVal <> DTSourced bArg bVal = DTSourced (aArg <> bArg) (aVal <> bVal)
	DTSourced arg val <> dt = DTSourced arg (val <> dt)
	dt <> DTSourced arg val = DTSourced arg (dt <> val)
instance Monoid DepsTree where
	mempty = DTIrrel
dtPath :: Path -> DepsTree -> DepsTree
dtPath [] dt = dt
dtPath (PPDir name:path) dt = DTDir $ bool DTIrrel (dtPath path dt) . (== name)
dtPath (PPSrcArg:path) dt = DTSourced (dtPath path dt) DTIrrel
dtPath (PPSrcVal:path) dt = DTSourced DTIrrel (dtPath path dt)
deps :: Path -> Fix' Value -> DepsTree -> DepsTree
deps path _ DTIrrel = mempty
deps path (VText _) _ = mempty
deps path (VDir entries) dt = fold $ fmap go $ M.toList entries
	where
		subDT = case dt of
			DTRel -> const DTRel
			DTDir f -> f
		go (name, v) = deps (PPDir name:path) v (subDT name)
deps path (VSourced src@(Source _ arg val)) dt = fold [
		sourceDeps path src valDT,
		deps (PPSrcArg:path) arg argDT,
		deps (PPSrcVal:path) (unFix val) valDT
	]
	where
		(argDT, valDT) = case dt of
			DTRel -> (DTRel, DTRel)
			DTSourced arg val -> (arg, val)
deps _ _ _ = mempty -- TODO
sourceDeps :: Path -> Source (Fix Value) -> DepsTree -> DepsTree
sourceDeps _ _ DTIrrel = mempty
sourceDeps path (Source STCommitLog arg _) dt
	= deps (PPSrcArg:path) arg $ dtPath [PPDir "index"] dt
sourceDeps path (Source STBackRef arg _) dt = deps (PPSrcArg:path) arg DTRel <> refDeps
	where
		refDeps = fromMaybe mempty $ do
			(nReal, nSrc) <- fixReal arg ^? _VText.to T.unpack.to readMaybe._Just
			path' <- pathBackRef path (nReal, nSrc)
			pure $ dtPath (reverse path') dt
sourceDeps path (Source STDescend arg _) dt
	= deps (PPSrcArg:path) arg (dtPath [PPDir "to"] DTRel) <> refDeps
	where
		refDeps = fromMaybe mempty $ do
			path <- fixReal arg ^? _VText.to T.unpack.to readMaybe._Just
			pure $ deps (PPSrcArg:path) arg (dtPath (PPDir "from":path) dt)
sourceDeps path (Source STAutoCommit arg _) dt
	= deps (PPSrcArg:path) arg $ dtPath [PPDir "value"] DTRel

fixReal :: Fix' Value -> Fix' Value
fixReal (VSourced (Source {val})) = fixReal $ unFix val
fixReal (VFakeReal val) = val
fixReal v = v

descend :: Pure f => Path -> (Value () -> f (Value ())) -> Value () -> f (Value ())
descend [] = id
descend (PPDir name:path) = real.dirAt name._Just.descend path
-- TODO

srcLens :: Pure f => SourceType -> (Value () -> f (Value ())) -> Value () -> f (Value ())
srcLens STCommitLog = dirAt "index"._Just.real
srcLens STDescend = \f arg -> fromMaybe (pure' arg) $ do
	to <- arg^?dirAt "to"._Just.real._VText.to T.unpack.to readMaybe._Just
	-- TODO: sources in from?
	pure $ (dirAt "from"._Just.descend to) f arg
srcLens STAutoCommit = \f currCommit -> let
		newCommit newVal = VDir $ M.fromList [
				("value",) $ newVal,
				("message",) $ VText "Auto Commit: TODO",
				("parents",) $ VDir $ M.fromList [
					("1",) $ currCommit
				]
			]
	in fromMaybe (pure' currCommit) $
		fmap (fmap newCommit . f) $ currCommit^?dirAt "value"._Just

srcVal :: Pure f => (Value () -> f (Value ())) -> Source () -> f (Source ())
srcVal f src@(Source st arg ()) = (#arg . real . srcLens st) f src

real :: Pure f => (Value () -> f (Value ())) -> Value () -> f (Value ())
real f (VSourced s) = fmap VSourced $ (srcVal.real) f s
real f (VFakeReal v) = fmap VFakeReal $ f v
real f v = f v

dirAt :: Pure f => T.Text -> (Maybe (Value ()) -> f (Maybe (Value ()))) -> Value () -> f (Value ())
dirAt name = _VDir . at name

testV = VSourced $ flip (Source STCommitLog) () $ VDir $ M.fromList [
		("HEAD",) $ VNoCommit,
		("index",) $ VDir $ M.fromList [ ]
		-- TODO: what if I want a source in the index?
	]

testV2 = VSourced $ flip (Source STAutoCommit) () $ VDir $ M.fromList [
		("value",) $ VDir $ M.fromList [ ],
		("message",) $ VText "Initial Commit",
		("parents",) $ VDir $ M.fromList [ ]
	]

testV3 = VSourced $ flip (Source STCommitLog) () $ VDir $ M.fromList [
		("HEAD",) $ VSourced $ flip (Source STDescend) () $ VDir $ M.fromList [
			("from",) $ VSourced $ flip (Source STBackRef) () $ VText $ T.pack $ show (0, 0),
			("to",) $ VText $ T.pack $ show [PPDir "refs", PPDir "heads", PPDir "master"]
		],
		("index",) $ VDir $ M.fromList [ ],
		("refs",) $ VSourced $ flip (Source STAutoCommit) () $ VDir $ M.fromList [
			("heads",) $ VDir $ M.fromList [
				("master",) $ VDir $ M.fromList [
					("value",) $ VDir $ M.fromList [ ],
					("message",) $ VText "Initial Commit",
					("parents",) $ VDir $ M.fromList [ ]
				]
			]
		]
	]

-- CommitLog - Dir
-- 	HEAD - Descend - Dir
-- 		from - BackRef - Text
-- 			(0, 0)
-- 		to - Text
-- 			[PPDir "refs", PPDir "heads", PPDir "master"]
--	index - Dir
--	refs - AutoCommit - Dir
--		heads - Dir
--			master - Dir
--				value - Dir
--				message - Text
--					Initial Commit
--				parents - Dir

-- TODO: backref
