/**
 * Pure Functional Programming Primitives
 * Provides immutable Result monads, function composition, and deep freeze helpers.
 */

export enum ResultTag {
  Ok = 'OK',
  Err = 'ERR',
}

export interface OkResult<T> {
  readonly tag: ResultTag.Ok;
  readonly value: T;
}

export interface ErrResult<E> {
  readonly tag: ResultTag.Err;
  readonly error: E;
}

export type Result<T, E> = OkResult<T> | ErrResult<E>;

export const ok = <T>(value: T): OkResult<T> =>
  Object.freeze({ tag: ResultTag.Ok, value });

export const err = <E>(error: E): ErrResult<E> =>
  Object.freeze({ tag: ResultTag.Err, error });

export const isOk = <T, E>(result: Result<T, E>): result is OkResult<T> =>
  result.tag === ResultTag.Ok;

export const isErr = <T, E>(result: Result<T, E>): result is ErrResult<E> =>
  result.tag === ResultTag.Err;

export const mapResult = <T, U, E>(
  result: Result<T, E>,
  fn: (val: T) => U
): Result<U, E> => (isOk(result) ? ok(fn(result.value)) : result);

export const flatMapResult = <T, U, E>(
  result: Result<T, E>,
  fn: (val: T) => Result<U, E>
): Result<U, E> => (isOk(result) ? fn(result.value) : result);

export const unwrapOr = <T, E>(result: Result<T, E>, fallback: T): T =>
  isOk(result) ? result.value : fallback;

export const pipe = <T>(initial: T, ...fns: ReadonlyArray<(arg: T) => T>): T =>
  fns.reduce((acc, fn) => fn(acc), initial);
