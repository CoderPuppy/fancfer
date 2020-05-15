module Fancfer.W3 where

import Control.Arrow
import Control.Category
import Control.Lens hiding (_Just)
import Control.Lens.TH (makePrisms)
import Control.Monad.Trans.Reader
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
import Debug.Trace
import GHC.OverloadedLabels
import Prelude hiding (id, (.))
import Text.Read (readMaybe)
import qualified Data.Map as M
import qualified Data.Text as T

import Fancfer.W4

data Value sv
	= VText T.Text
	| VDir (M.Map T.Text (Value sv))
	| VSourced (Source sv)
	| VBackRefCycle -- TODO
	| VFakeReal (Value sv)
	deriving (Show, Eq)
_VDir :: (Choice p, Pure f) => p (M.Map T.Text (Value sv)) (f (M.Map T.Text (Value sv))) -> p (Value sv) (f (Value sv))
_VDir = dimap (\case { VDir a -> Left a; v -> Right v }) (either (fmap VDir) pure') . left'
_VText :: (Choice p, Pure f) => p T.Text (f T.Text) -> p (Value sv) (f (Value sv))
_VText = dimap (\case { VText a -> Left a; v -> Right v }) (either (fmap VText) pure') . left'
_VSourced :: (Choice p, Pure f) => p (Source sv) (f (Source sv)) -> p (Value sv) (f (Value sv))
_VSourced = dimap (\case { VSourced a -> Left a; v -> Right v }) (either (fmap VSourced) pure') . left'

data SourceType = STCommitLog | STBackRef | STDescend | STAutoCommit deriving (Show, Eq)
-- STRepo, STBackRef, STCommitLog, STDescend, STAutoCommit
data Source sv = Source {
	_type :: SourceType,
	arg :: Value sv,
	val :: sv
} deriving (Show, Eq)
instance (Strong p, Functor f) => IsLabel "type" (p SourceType (f SourceType) -> p (Source sv) (f (Source sv))) where
	fromLabel = dimap (\c@(Source {_type}) -> (_type, c)) (\(_type, c) -> fmap (\_type -> c {_type}) _type) . first'
instance (Strong p, Functor f) => IsLabel "arg" (p (Value sv) (f (Value sv)) -> p (Source sv) (f (Source sv))) where
	fromLabel = dimap (\c@(Source {arg}) -> (arg, c)) (\(arg, c) -> fmap (\arg -> c {arg}) arg) . first'
instance (Strong p, Functor f) => IsLabel "val" (p sv (f sv) -> p (Source sv) (f (Source sv))) where
	fromLabel = dimap (\c@(Source {val}) -> (val, c)) (\(val, c) -> fmap (\val -> c {val}) val) . first'

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
-- TODO
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

class FMessage f where
	fMessage :: f (Maybe T.Text -> f a) -> f a

newtype FFT m a = FFT { runFFT :: StateT [Value' ()] (RT (Maybe T.Text) m) a }
	deriving (Functor, Applicative, Monad, Contravariant)
instance Pure m => Pure (FFT m) where
	pure' a = FFT $ StateT $ \s -> pure' (a, s)
instance Pure m => FBackRef (FFT m) where
	fBackRef' l f c =
		FFT $ StateT $ \zp ->
		fmap (\((d, zp), r) -> ((d, r), zp)) $
		runWriterT $ flip l (c, zp) $ Indexed $ \i (a, zp) -> WriterT $
		fmap (\((c, b), zp) -> ((b, zp), c)) $
		flip runStateT zp $ runFFT $ f i a
	fBackRef l f c =
		FFT $ StateT $ \zp ->
		fmap (\((d, zp), r) -> ((d, getFirst r), zp)) $
		runWriterT $ flip l (c, zp) $ Indexed $ \i (a, zp) -> WriterT $
		fmap (\((c, b), zp) -> ((b, zp), First $ Just c)) $
		flip runStateT zp $ runFFT $ f i a
deriving instance (Base b m, Pure m) => Base b (FFT m)
instance (Pure m, FakeMonad m) => FMessage (FFT m) where
	fMessage f = FFT $ StateT $ \s -> RT $ fmap
		(\f r ->
			fakeJoin $ fmap ($ r) $ fakeJoin $
			fmap (runRT . uncurry ($) . first (runStateT . runFFT . ($ r))) $ f r)
		(runRT $ flip runStateT s $ runFFT f)
instance Trans FFT where
	lift = FFT . lift . lift

runGet :: (FBackRef f, FMessage f) => FFT (Const r) b -> (r -> f a) -> f a
runGet f k = fmap snd $ fBackRef'
	(\f ((), zp) -> indexed f () (zp, zp))
	(\() zp ->
		fmap (, ()) $ k $ getConst $
		runRT $ flip runStateT zp $ runFFT f)
	()

mget :: Base (Const r) f => ((a -> f b) -> s -> f t) -> (a -> r) -> s -> f t
mget o f v = o (liftBase . Const . f) v

descend :: (Pure f, FBackRef f, FMessage f) => Path -> (Value () -> f (Value ())) -> Value () -> f (Value ())
descend [] = id
descend (PPDir name:path) = real.dirAt name._Just.descend path
-- TODO

srcLens :: (Pure f, FBackRef f, FMessage f) => SourceType -> (Value () -> f (Value ())) -> Value () -> f (Value ())
srcLens STCommitLog = real.dirAt "index"._Just.fakeReal
srcLens STBackRef = \f arg -> runGet
	(mget (real._VText.to T.unpack.to readMaybe._Just) pure arg)
	$ \(First ns) ->
	fmap (const arg) $ fromMaybe (pure' ()) $ do
		(nReal, nSrc) <- ns
		pure $ fmap (const ()) $ fBackRef
			(\f ((), zp) -> fmap (first $ const ()) $ zipperBackRef (nReal, nSrc) f (VBackRefCycle, zp))
			(\path v -> fmap ((),) $ f v)
			()
srcLens STDescend = \f arg -> runGet
	(mget (real.dirAt "to"._Just.real._VText.to T.unpack.to readMaybe._Just) pure arg)
	$ \(First to) ->
	fromMaybe (pure' arg) $ do
		to <- to
		-- TODO: sources in from?
		pure $ (dirAt "from"._Just.descend to) f arg
srcLens STAutoCommit = \f currCommit -> let
		newCommit currVal newVal msg | currVal == newVal = currCommit
		newCommit currVal newVal msg = VDir $ M.fromList [
				("value",) $ newVal,
				("message",) $ VText $ maybe "Auto Commit" ("Auto Commit: " <>) msg,
				("parents",) $ VDir $ M.fromList [
					("1",) $ currCommit
				]
			]
	in runGet
		(mget (real.dirAt "value"._Just) pure currCommit)
		$ \(First currVal) -> fromMaybe (pure' currCommit) $
		fmap (fMessage . fmap (pure' .) . uncurry fmap . (newCommit &&& f)) currVal

srcArg :: (Pure f, FBackRef f) => (Value () -> f (Value ())) -> Source () -> f (Source ())
srcArg f = fmap fst . fBackRef'
	(\f (Source st arg (), zp) ->
		fmap (\(arg, V'SourcedArg st ():zp) -> (Source st arg (), zp)) $
		indexed f () (arg, V'SourcedArg st ():zp))
	(\() arg -> fmap ((),) $ f arg)

srcVal :: (Pure f, FBackRef f, FMessage f) => (Value () -> f (Value ())) -> Source () -> f (Source ())
srcVal f src@(Source st arg ()) = (srcArg . fakeReal . srcLens st) f src

real :: (Pure f, FBackRef f, FMessage f) => (Value () -> f (Value ())) -> Value () -> f (Value ())
real f (VSourced s) = fmap VSourced $ (srcVal.real) f s
real f (VFakeReal v) = fmap VFakeReal $ real f v
real f v = f v

fakeReal :: (Pure f, FBackRef f, FMessage f) => (Value () -> f (Value ())) -> Value () -> f (Value ())
fakeReal f (VSourced s) = fmap VSourced $ (srcVal.real) f s
fakeReal f (VFakeReal v) = fmap VFakeReal $ f v
fakeReal f v = f v

dirAt :: (Pure f, FBackRef f) => T.Text -> (Maybe (Value ()) -> f (Maybe (Value ()))) -> Value () -> f (Value ())
dirAt name = _VDir . \f -> fmap fst . fBackRef'
	(\f (entries, zp) ->
		fmap (\(v, V'Dir entries name:zp) -> (M.alter (const v) name entries, zp)) $
		indexed f () (M.lookup name entries, V'Dir (M.delete name entries) name:zp))
	(\() v -> fmap ((),) $ f v)

dirEntries :: forall p f. (Indexable T.Text p, Monad f, Pure f, FBackRef f) =>
	p (Maybe (Value ())) (f (Maybe (Value ()))) ->
	Value () -> f (Value ())
dirEntries = _VDir . \f entries -> ifoldr (go f) (pure' entries) entries
	where go f name v entries = do
		entries <- entries
		fmap fst $ fBackRef'
			(\f (entries, zp) ->
				fmap (\(v, V'Dir entries name:zp) -> (M.alter (const v) name entries, zp)) $
				indexed f () (M.lookup name entries, V'Dir (M.delete name entries) name:zp))
			(\() v -> fmap ((),) $ indexed f name v)
			entries

testV = VSourced $ flip (Source STCommitLog) () $ VDir $ M.fromList [
		("HEAD",) $ VText "NO COMMIT",
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

test_get v l = snd $ runIdentity $ runWriterT $ runRT $ flip runStateT [] $ runFFT $
	flip l v $ \v -> lift (tell [v]) *> pure v
test_set v msg l v' = fst $ runIdentity $ ($ msg) $ runIdentity $ runRT $ flip runStateT [] $ runFFT $
	l (const $ pure' v') v
test_zp v l = snd $ runIdentity $ runWriterT $ runRT $ flip runStateT [] $ runFFT $ flip l v $
	\v -> FFT $ StateT $ \zp -> RT $ tell [zp] *> pure (const $ pure (v, zp))

-- TODO: coalescing updates
-- TODO: cycle detection
-- TODO: external state
