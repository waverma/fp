﻿using System;

namespace ResultOfTask
{
    public class None
    {
        private None()
        {
        }
    }
    public struct Result<T>
    {
        public Result(string error, T value = default(T))
        {
            Error = error;
            Value = value;
        }
        public string Error { get; }
        internal T Value { get; }
        public T GetValueOrThrow()
        {
            if (IsSuccess) return Value;
            throw new InvalidOperationException($"No value. Only Error {Error}");
        }
        public bool IsSuccess => Error == null;

        public Result<T> ReplaceError(Func<string, string> func)
        {
            return IsSuccess ? this : Result.Fail<T>(func(Error));
        }

        public Result<T> RefineError(string postingResultsToDb)
        {
            return IsSuccess ? this : Result.Fail<T>($"{postingResultsToDb}. {Error}");
        }
    }

    public static class Result
    {
        public static Result<T> AsResult<T>(this T value)
        {
            return Ok(value);
        }

        public static Result<T> Ok<T>(T value)
        {
            return new Result<T>(null, value);
        }

        public static Result<T> Fail<T>(string e)
        {
            return new Result<T>(e);
        }

        public static Result<T> Of<T>(Func<T> f, string error = null)
        {
            try
            {
                return Ok(f());
            }
            catch (Exception e)
            {
                return Fail<T>(error ?? e.Message);
            }
        }

        public static Result<TOutput> Then<TInput, TOutput>(this Result<TInput> input, Func<TInput, TOutput> continuation)
        {
            return input.Then(i => Of(() => continuation(i)));
        }

        public static Result<TOutput> Then<TInput, TOutput>(this Result<TInput> input, Func<TInput, Result<TOutput>> continuation)
        {
            return !input.IsSuccess 
                ? new Result<TOutput>(input.Error) 
                : continuation(input.Value);
        }

        public static Result<TInput> OnFail<TInput>(this Result<TInput> input, Action<string> handleError)
        {
            if (!input.IsSuccess) handleError(input.Error); 
            return input;
        }
    }
}