#ifndef MY_COMPILER_INCLUDED
#define MY_COMPILER_INCLUDED

/* Copyright (c) 2010, 2022, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   Without limiting anything contained in the foregoing, this file,
   which is part of C Driver for MySQL (Connector/C), is also subject to the
   Universal FOSS Exception, version 1.0, a copy of which can be found at
   http://oss.oracle.com/licenses/universal-foss-exception.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  Header for compiler-dependent features.

  Intended to contain a set of reusable wrappers for preprocessor
  macros, attributes, pragmas, and any other features that are
  specific to a target compiler.
*/

#include <stddef.h> /* size_t */

#if defined __GNUC__
/*
  Convenience macro to test the minimum required GCC version.
  These should be used with care as Clang also sets __GNUC__ and
  __GNUC_MINOR__ (currently to 4.2). Prefer using feature specific
  CMake checks in configure.cmake instead.
*/
#  define MY_GNUC_PREREQ(maj, min) \
    ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#  define GCC_VERSION (__GNUC__ * 1000 + __GNUC_MINOR__)
#else
#  define MY_GNUC_PREREQ(maj, min) (0)
#endif

/*
  The macros below are borrowed from include/linux/compiler.h in the
  Linux kernel. Use them to indicate the likelyhood of the truthfulness
  of a condition. This serves two purposes - newer versions of gcc will be
  able to optimize for branch predication, which could yield siginficant
  performance gains in frequently executed sections of the code, and the
  other reason to use them is for documentation
*/
#ifdef HAVE_BUILTIN_EXPECT

// likely/unlikely are likely to clash with other symbols, do not #define
#if defined(__cplusplus)
inline bool likely(bool expr)
{
  return __builtin_expect(expr, true);
}
inline bool unlikely(bool expr)
{
  return __builtin_expect(expr, false);
}
#else
#  define likely(x)    __builtin_expect((x),1)
#  define unlikely(x)  __builtin_expect((x),0)
#endif

#else  /* HAVE_BUILTIN_EXPECT */

#if defined(__cplusplus)
inline bool likely(bool expr)
{
  return expr;
}
inline bool unlikely(bool expr)
{
  return expr;
}
#else
#  define likely(x)    (x)
#  define unlikely(x)  (x)
#endif

#endif  /* HAVE_BUILTIN_EXPECT */

/* Comunicate to the compiler the unreachability of the code. */
#ifdef HAVE_BUILTIN_UNREACHABLE
#  define MY_ASSERT_UNREACHABLE()   __builtin_unreachable()
#else
#  define MY_ASSERT_UNREACHABLE()  do { assert(0); } while (0)
#endif

#if defined __GNUC__ || defined __SUNPRO_C || defined __SUNPRO_CC
/* Specifies the minimum alignment of a type. */
# define MY_ALIGNOF(type)   __alignof__(type)
/* Determine the alignment requirement of a type. */
# define MY_ALIGNED(n)      __attribute__((__aligned__((n))))
/* Microsoft Visual C++ */
#elif defined _MSC_VER
# define MY_ALIGNOF(type)   __alignof(type)
# define MY_ALIGNED(n)      __declspec(align(n))
#else /* Make sure they are defined for other compilers. */
# define MY_ALIGNOF(type)
# define MY_ALIGNED(size)
#endif

/* Visual Studio requires '__inline' for C code */
#if !defined(__cplusplus) && defined(_MSC_VER)
# define inline __inline
#endif

/* Provide __func__ macro definition for Visual Studio. */
#if defined(_MSC_VER)
#  define __func__ __FUNCTION__
#endif

/**
  C++ Type Traits
*/
#ifdef __cplusplus

/**
  Opaque storage with a particular alignment.
  Partial specialization used due to MSVC++.
*/
template<size_t alignment> struct my_alignment_imp;
template<> struct MY_ALIGNED(1) my_alignment_imp<1> {};
template<> struct MY_ALIGNED(2) my_alignment_imp<2> {};
template<> struct MY_ALIGNED(4) my_alignment_imp<4> {};
template<> struct MY_ALIGNED(8) my_alignment_imp<8> {};
template<> struct MY_ALIGNED(16) my_alignment_imp<16> {};

/**
  A POD type with a given size and alignment.

  @remark If the compiler does not support a alignment attribute
          (MY_ALIGN macro), the default alignment of a double is
          used instead.

  @tparam size        The minimum size.
  @tparam alignment   The desired alignment: 1, 2, 4, 8 or 16.
*/
template <size_t size, size_t alignment>
struct my_aligned_storage
{
  union
  {
    char data[size];
    my_alignment_imp<alignment> align;
  };
};

#if __cpp_attributes && defined(__has_cpp_attribute)
#if __has_cpp_attribute(nodiscard)
#define MY_NODISCARD [[nodiscard]]
#elif __has_cpp_attribute(gnu::warn_unused_result)
#define MY_NODISCARD [[gnu::warn_unused_result]]
#endif /* __has_cpp_attribute(gnu::warn_unused_result) */
#endif /* __cpp_attributes && defined(__has_cpp_attribute) */

#endif /* __cplusplus */

/*
  Disable MY_ATTRIBUTE for Sun Studio and Visual Studio.
  Note that Sun Studio supports some __attribute__ variants,
  but not format or unused which we use quite a lot.
*/
#ifndef MY_ATTRIBUTE
#if defined(__GNUC__)
#  define MY_ATTRIBUTE(A) __attribute__(A)
#else
#  define MY_ATTRIBUTE(A)
#endif
#endif

#ifndef __has_attribute
# define __has_attribute(x) 0
#endif

#ifndef MY_NODISCARD
#define MY_NODISCARD MY_ATTRIBUTE((warn_unused_result))
#endif /* MY_NODISCARD */

#if __has_attribute(no_sanitize_undefined)
# define SUPPRESS_UBSAN __attribute__((no_sanitize_undefined))
#else
# define SUPPRESS_UBSAN
#endif

#endif /* MY_COMPILER_INCLUDED */
