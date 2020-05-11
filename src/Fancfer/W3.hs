module Fancfer.W3 where

import Control.Arrow
import Control.Category
import Control.Lens hiding (_Just)
import Control.Lens.TH (makePrisms)
import Control.Monad.Trans.Class
import Control.Monad.Trans.State
import Control.Monad.Trans.Writer.Lazy
import Data.Bool
import Data.Fix
import Data.Foldable
import Data.Functor.Identity
import Data.Maybe
import Data.Monoid
import Data.Profunctor
import Data.Tuple
import GHC.OverloadedLabels
import Prelude hiding (id, (.))
import Text.Read (readMaybe)
import qualified Data.Map as M
import qualified Data.Text as T
import Debug.Trace

class Functor f => Pure f where
	pure' :: a -> f a
	default pure' :: Applicative f => a -> f a
	pure' = pure
instance Monoid r => Pure (Const r)
instance Monoid r => Pure ((,) r)
instance (Pure m, Monoid w) => Pure (WriterT w m) where
	pure' = WriterT . pure' . (, mempty)
instance Pure Identity
instance Pure IO

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

data Value' sv
	= V'Dir (M.Map T.Text (Value sv)) T.Text
	| V'SourcedArg SourceType sv
	| V'SourcedVal SourceType (Value sv)
	| V'FakeReal
	deriving (Show)

zipperBackRef :: (Indexable Path p, Pure f) => (Int, Int) ->
	(p (Value sv, [Value' sv]) (f (Value sv, [Value' sv]))) ->
	(Value sv, [Value' sv]) -> f (Value sv, [Value' sv])
zipperBackRef (0, 0) f (v, zp) = indexed f ([] :: Path) (v, zp)
zipperBackRef _ f (v, []) = pure' (v, [])
-- zipperBackRef (0, nSrc) f (v, V'SourcedVal st arg:zp) = fmap (error "TODO") $ zipperBackRef (0, nSrc - 1) f (VSourced (Source st arg (error "TODO")), zp)
-- zipperBackRef (nReal, nSrc) f (v, V'SourcedVal st arg:zp) = fmap (error "TODO") $ zipperBackRef (nReal, nSrc) f (VSourced (Source st arg (error "TODO")), zp)
zipperBackRef (nReal, nSrc) f (v, V'SourcedArg st sv:zp)
	= fmap after $ zipperBackRef (nReal - 1, nSrc) f' (VSourced (Source st v sv), zp)
	where
		after (VSourced (Source st arg sv), zp) = (arg, V'SourcedArg st sv:zp)
		f' = Indexed $ \path (v, zp) -> indexed f (PPSrcArg:path) (v, zp)
zipperBackRef (nReal, nSrc) f (v, V'Dir entries name:zp)
	= fmap after $ zipperBackRef (nReal - 1, nSrc) f' (VDir (M.insert name v entries), zp)
	where
		after (VDir entries, zp) = (fromJust $ M.lookup name entries, V'Dir (M.delete name entries) name:zp)
		f' = Indexed $ \path (v, zp) -> indexed f (PPDir name:path) (v, zp)
-- zipperBackRef zp (0, 0) = Just zp
-- zipperBackRef [] _ = Nothing
-- zipperBackRef (V'SourcedVal _ _:zp) (0, nSrc) = zipperBackRef zp (0, nSrc - 1)
-- zipperBackRef (V'SourcedVal _ _:zp) (nReal, nSrc) = zipperBackRef zp (nReal, nSrc)
-- zipperBackRef (V'SourcedArg _ _:zp) (nReal, nSrc) = zipperBackRef zp (nReal - 1, nSrc)
-- zipperBackRef (V'Dir _ _:zp) (nReal, nSrc) = zipperBackRef zp (nReal - 1, nSrc)

fixReal :: Fix' Value -> Fix' Value
fixReal (VSourced (Source {val})) = fixReal $ unFix val
fixReal (VFakeReal val) = val
fixReal v = v

class Pure f => FBackRef f where
	fBackRef' ::
		(
			forall g. Functor g =>
			(Indexed i (a, [Value' ()]) (g (b, [Value' ()]))) ->
			(c, [Value' ()]) -> g (d, [Value' ()])
		) ->
		(i -> a -> f (r, b)) ->
		c -> f (d, r)
	fBackRef ::
		(
			forall g. Pure g =>
			(Indexed i (a, [Value' ()]) (g (b, [Value' ()]))) ->
			(c, [Value' ()]) -> g (d, [Value' ()])
		) ->
		(i -> a -> f (r, b)) ->
		c -> f (d, Maybe r)

newtype FBackRefT m a = FBackRefT { runFBackRefT :: StateT [Value' ()] m a }
	deriving (Functor, Applicative, Monad, MonadTrans, Contravariant)
instance Pure m => Pure (FBackRefT m) where
	pure' a = FBackRefT $ StateT $ \s -> pure' (a, s)
instance Pure m => FBackRef (FBackRefT m) where
	fBackRef' l f c =
		FBackRefT $ StateT $ \zp ->
		fmap (\((d, zp), r) -> ((d, r), zp)) $
		runWriterT $ flip l (c, zp) $ Indexed $ \i (a, zp) -> WriterT $
		fmap (\((c, b), zp) -> ((b, zp), c)) $
		flip runStateT zp $ runFBackRefT $ f i a
	fBackRef l f c =
		FBackRefT $ StateT $ \zp ->
		fmap (\((d, zp), r) -> ((d, getFirst r), zp)) $
		runWriterT $ flip l (c, zp) $ Indexed $ \i (a, zp) -> WriterT $
		fmap (\((c, b), zp) -> ((b, zp), First $ Just c)) $
		flip runStateT zp $ runFBackRefT $ f i a

liftFBackRefT :: Functor m => m a -> FBackRefT m a
liftFBackRefT m = FBackRefT $ StateT $ \s -> fmap (, s) m

fBackRef_runGet :: FBackRef f => FBackRefT (Const r) b -> (r -> f a) -> f a
-- fBackRef_runGet f k = fBackRef $ \s -> (, s) $ k $ getConst $ runStateT (runFBackRefT f) s
fBackRef_runGet f k = fmap snd $ fBackRef'
	(\f ((), zp) -> indexed f () (zp, zp))
	(\() zp -> fmap (, ()) $ k $ getConst $ runStateT (runFBackRefT f) zp)
	()

fBackRefT_get :: ((a -> FBackRefT (Const r) b) -> s -> FBackRefT (Const r) t) -> (a -> r) -> s -> FBackRefT (Const r) t
fBackRefT_get o f v = o (liftFBackRefT . Const . f) v

descend :: (Pure f, FBackRef f) => Path -> (Value () -> f (Value ())) -> Value () -> f (Value ())
descend [] = id
descend (PPDir name:path) = real.dirAt name._Just.descend path
-- TODO

srcLens :: (Pure f, FBackRef f) => SourceType -> (Value () -> f (Value ())) -> Value () -> f (Value ())
srcLens STCommitLog = dirAt "index"._Just.real
srcLens STBackRef = \f arg ->
	fBackRef_runGet
		(fBackRefT_get (real._VText.to T.unpack.to readMaybe._Just) pure arg)
		$ \(First ns) ->
		fmap (const arg) $ fromMaybe (pure' ()) $ do
			(nReal, nSrc) <- ns
			pure $ fmap (const ()) $ fBackRef
				(\f ((), zp) -> fmap (first $ const ()) $ zipperBackRef (nReal, nSrc) f (VBackRefCycle, zp))
				(\path v -> fmap ((),) $ f v)
				()
srcLens STDescend = \f arg ->
	fBackRef_runGet
		(fBackRefT_get (dirAt "to"._Just.real._VText.to T.unpack.to readMaybe._Just) pure arg)
		$ \(First to) ->
		fromMaybe (pure' arg) $ do
			to <- to
			-- TODO: sources in from?
			pure $ (dirAt "from"._Just.descend to) f arg
srcLens STAutoCommit = \f currCommit ->
	let
		newCommit newVal = VDir $ M.fromList [
				("value",) $ newVal,
				("message",) $ VText "Auto Commit: TODO",
				("parents",) $ VDir $ M.fromList [
					("1",) $ currCommit
				]
			]
	in fBackRef_runGet
		(fBackRefT_get (dirAt "value"._Just) pure currCommit)
		(fromMaybe (pure' currCommit) .  fmap (fmap newCommit . f) . getFirst)

srcArg :: (Pure f, FBackRef f) => (Value () -> f (Value ())) -> Source () -> f (Source ())
srcArg f = fmap fst . fBackRef'
	(\f (Source st arg (), zp) ->
		fmap (\(arg, V'SourcedArg st ():zp) -> (Source st arg (), zp)) $
		indexed f () (arg, V'SourcedArg st ():zp))
	(\() arg -> fmap ((),) $ f arg)

srcVal :: (Pure f, FBackRef f) => (Value () -> f (Value ())) -> Source () -> f (Source ())
srcVal f src@(Source st arg ()) = (srcArg . real . srcLens st) f src

real :: (Pure f, FBackRef f) => (Value () -> f (Value ())) -> Value () -> f (Value ())
real f (VSourced s) = fmap VSourced $ (srcVal.real) f s
real f (VFakeReal v) = fmap VFakeReal $ f v
real f v = f v

dirAt :: (Pure f, FBackRef f) => T.Text -> (Maybe (Value ()) -> f (Maybe (Value ()))) -> Value () -> f (Value ())
dirAt name = _VDir . \f -> fmap fst . fBackRef'
	(\f (entries, zp) ->
		fmap (\(v, V'Dir entries name:zp) -> (M.alter (const v) name entries, zp)) $
		indexed f () (M.lookup name entries, V'Dir (M.delete name entries) name:zp))
	(\() v -> fmap ((),) $ f v)
-- dirAt name = _VDir . at name

dirEntries :: forall p f. (Indexable T.Text p, Monad f, Pure f, FBackRef f) =>
	p (Maybe (Value ())) (f (Maybe (Value ()))) ->
	Value () -> f (Value ())
dirEntries = _VDir . \f entries -> ifoldr (go f) (pure' entries) entries
	where
		go :: p (Maybe (Value ())) (f (Maybe (Value ()))) -> T.Text -> Value () ->
			f (M.Map T.Text (Value ())) -> f (M.Map T.Text (Value ()))
		go f name v entries = do
			entries <- entries
			fmap fst $ fBackRef'
				(\f (entries, zp) ->
					fmap (\(v, V'Dir entries name:zp) -> (M.alter (const v) name entries, zp)) $
					indexed f () (M.lookup name entries, V'Dir (M.delete name entries) name:zp))
				(\() v -> fmap ((),) $ indexed f name v)
				entries

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

testV4 = VDir $ M.fromList [
		("fiz",) $ VSourced $ flip (Source STDescend) () $ VDir $ M.fromList [
				("from",) $ VSourced $ flip (Source STBackRef) () $ VText $ T.pack $ show (2, 0),
				("to",) $ VText $ T.pack $ show [PPDir "buz"]
			],
		("buz",) $ VText "baz",
		("testing",) $ VSourced $ flip (Source STBackRef) () $ VText $ T.pack $ show (1, 0)
	]

test_get v l = snd $ runIdentity $ runWriterT $ flip runStateT [] $ runFBackRefT $ flip l v $
	\v -> liftFBackRefT (tell [v]) *> pure v
test_set v l v' = fst $ runIdentity $ flip runStateT [] $ runFBackRefT $ l (const $ pure' v') v
test_zp v l = snd $ runIdentity $ runWriterT $ flip runStateT [] $ runFBackRefT $ flip l v $
	\v -> FBackRefT $ StateT $ \zp -> tell [zp] *> pure (v, zp)

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
