module Fancfer.W4 where

import Control.Applicative
import Control.Monad
import Control.Monad.Trans.Reader
import Control.Monad.Trans.State
import Control.Monad.Trans.Writer.Lazy
import Data.Fix
import Data.Functor.Contravariant
import Data.Functor.Identity
import Data.Profunctor
import RIO

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

class Trans t where
	lift :: Pure f => f a -> t f a
instance Trans (StateT s) where
	lift f = StateT $ \s -> fmap (, s) f
instance Trans (ReaderT r) where
	lift = ReaderT . const
class Base b f | f -> b where
	liftBase :: b a -> f a
instance Base (Const r) (Const r) where
	liftBase = id
instance (Base b m, Functor m) => Base b (StateT s m) where
	liftBase f = StateT $ \s -> fmap (, s) $ liftBase f
instance Base b m => Base b (ReaderT s m) where
	liftBase = ReaderT . const . liftBase

_Just :: (Choice p, Pure f) => p a (f b) -> p (Maybe a) (f (Maybe b))
_Just = dimap (\case {
		Just a -> Left a;
		Nothing -> Right ()
	}) (either (fmap Just) (const $ pure' Nothing)) . left'
type Fix' f = f (Fix f)
_Fix :: (Profunctor p, Functor f) => p (Fix' a) (f (Fix' b)) -> p (Fix a) (f (Fix b))
_Fix = dimap unFix (fmap Fix)

class FakeMonad m where
	fakeJoin :: m (m a) -> m a
	default fakeJoin :: Monad m => m (m a) -> m a
	fakeJoin = join
instance FakeMonad (Const r) where
	fakeJoin = Const . getConst
instance (Monoid w, Monad m) => FakeMonad (WriterT w m)
instance FakeMonad Identity

newtype RT r m a = RT { runRT :: m (r -> m a) }
instance Functor m => Functor (RT r m) where
	fmap f = RT . fmap (fmap f .) . runRT
instance Pure m => Pure (RT r m) where
	pure' = RT . pure' . const . pure'
instance Applicative m => Applicative (RT r m) where
	pure = RT . pure . const . pure
	RT f <*> RT a = RT $ liftA2 (<*>) <$> f <*> a
instance Monad m => Monad (RT r m) where
	RT a >>= f = RT $ do
		a <- a
		pure $ \r -> do
			a <- a r
			b <- runRT (f a)
			b <- b r
			pure b
instance (Contravariant m, Functor m) => Contravariant (RT r m) where
	contramap f = RT . contramap ((fmap f .) . ($)) . runRT
instance Trans (RT r) where
	lift = RT . fmap ((pure' .) . const)
instance (Base b m, Pure m) => Base b (RT r m) where
	liftBase = RT . fmap ((pure' .) . const) . liftBase

-- TODO: find an m that satisfies Contravariant m, Monad m, I think it's equivalent to ⊤
