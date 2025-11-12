/* ************************************************************************** */

/*
	- License: MIT LICENSE
	- Author: https://github.com/Arty3

	- Requires:
		- C++20 or above,
		- MSVC / GCC / Clang
		- Windows 10 or above, alternatively Linux

	- Notes:
		- GCC does not support vector calls for
		  some ungodly reason, so use clang instead
*/

#pragma once

#if defined(_MSC_VER)
#define __COMPILER_MSVC_
#elif defined(__clang__) && defined(__GNUC__)
#define __COMPILER_CLANG_
#pragma clang diagnostic ignored "-Wignored-attributes"
#elif defined(__GNUC__) && defined(__GNUC_PATCHLEVEL__)
#define __COMPILER_GCC_
#pragma GCC diagnostic ignored "-Wattributes"
#pragma GCC diagnostic ignored "-Wignored-attributes"
#else
#error "Unsupported compiler. This translation unit requires MSVC, Clang or GCC."
#endif

#if defined(_WIN32) || defined(_WIN64)
#define __PLATFORM_WINDOWS_
#elif defined(__linux__)
#define __PLATFORM_LINUX_
#else
#error "Unsupported platform. This translation unit requires Windows or Linux."
#endif

#if defined(__PLATFORM_WINDOWS_) && defined(_KERNEL_MODE)
#define __WINDOWS_KERNEL_
#if !defined(__COMPILER_MSVC_)
#error "Windows kernel mode is only supported by MSVC."
#endif
#endif

#if defined(__COMPILER_CLANG_) || defined(__COMPILER_GCC_)
#if !defined(__has_builtin)
#define __has_builtin(x) 0
#endif
#if !defined(__has_feature)
#define __has_feature(x) 0
#endif
#endif

#if defined(__PLATFORM_WINDOWS_)
#if defined(_M_X64) || defined(_M_AMD64)
#define __ARCH_X64_
#elif defined(_M_IX86)
#define __ARCH_X86_
#if defined(__COMPILER_MSVC_)
#pragma message("warning: 32-bit architecture lacks support.")
#else
#warning "32-bit architecture lacks support."
#endif
#elif defined(_M_ARM64)
#define __ARCH_ARM64_
#endif
#elif defined(__PLATFORM_LINUX_)
#if defined(__x86_64__) || defined(__amd64__)
#define __ARCH_X64_
#elif defined(__i386__)
#define __ARCH_X86_
#if defined(__COMPILER_MSVC_)
#pragma message("warning: 32-bit architecture lacks support.")
#else
#warning "32-bit architecture lacks support."
#endif
#elif defined(__aarch64__)
#define __ARCH_ARM64_
#endif
#else
#error "Unsupported architecture: This translation unit requires x86 or x86-64."
#endif

#if defined(__COMPILER_MSVC_)
#if defined(_MSVC_LANG) && _MSVC_LANG < 202002L
#error "This translation unit requires C++20 or above."
#endif
#elif defined(__COMPILER_CLANG_) || defined(__COMPILER_GCC_)
#if __cplusplus < 202002L
#error "This translation unit requires C++20 or above."
#endif
#endif

#if defined(__WINDOWS_KERNEL_)
#include <Intrin.h>
#include <ntifs.h>
#elif defined(__PLATFORM_WINDOWS_)
#include <Windows.h>
#include <Intrin.h>
#include <random>
#include <tuple>
#if NTDDI_VERSION < NTDDI_WIN10_VB
#error "This translation unit requires Windows 10 or above."
#endif
#elif defined(__PLATFORM_LINUX_)
#include <signal.h>
#include <unistd.h>
#include <cstdint>
#include <random>
#include <tuple>
#endif

#if !defined(OBFUSCATOR_ENABLE_RA_TAMPER)
#define OBFUSCATOR_ENABLE_RA_TAMPER 1
#endif

/* AArch64: default to NO tamper unless explicitly forced */
#if defined(__ARCH_ARM64_)
#if !defined(OBFUSCATOR_ARM64_FORCE_TAMPER)
#define OBFUSCATOR_ARM64_FORCE_TAMPER 0
#endif
#else
#define OBFUSCATOR_ARM64_FORCE_TAMPER 1
#endif

#if defined(__ARCH_ARM64_) && defined(__COMPILER_CLANG_)
#if __has_feature(shadow_call_stack)
#define __NO_SCS_	__attribute__((no_sanitize("shadow-call-stack")))
#else
#define __NO_SCS_
#endif
#else
#define __NO_SCS_
#endif

/* To clarify, the weird naming convention: __SYMBOL_
 * is to avoid polluting the global macro namespace,
 * since when we include the header, we can't scope
 * these macros away, so best to name them poorly */

#if defined(__COMPILER_MSVC_)
#define __FORCE_INLINE_		__forceinline
#define __NO_INLINE_		__declspec(noinline)
#define __NO_STACK_PROTECT_	__declspec(safebuffers)
#define __NO_CFG_			__declspec(guard(nocf))
#define __ALIGN_(x)			__declspec(align(x))
#define __RESTRICT_			__restrict
#define __DISCARD_BRANCH_	__assume(0)
#elif defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_)
#define __FORCE_INLINE_		__attribute__((always_inline)) inline
#define __NO_INLINE_		__attribute__((noinline))
#define __NO_STACK_PROTECT_	__attribute__((no_stack_protector))
#define __DEPRECATED_(x)	__attribute__((deprecated(x)))
#if defined(__COMPILER_CLANG_) && defined(__has_feature) && __has_feature(cfi)
#define __NO_CFG_			__attribute__((no_sanitize("cfi")))
#elif (defined(__COMPILER_CLANG_) && __clang_major__ >= 7) \
	|| (defined(__COMPILER_GCC_) && __GNUC__ >= 9)
#define __NO_CFG_			__attribute__((nocf_check))
#else
#define __NO_CFG_
#endif
#define __ALIGN_(x)			__attribute__((aligned(x)))
#define __RESTRICT_			__restrict__
#define __DISCARD_BRANCH_	__builtin_unreachable()
#endif

#if !defined(__WINDOWS_KERNEL_)
#define __UNLIKELY_		[[unlikely]]
#define __LIKELY_		[[likely]]
#define __MAYBE_UNUSED_	[[maybe_unused]]
#else
#define __UNLIKELY_
#define __LIKELY_
#define __MAYBE_UNUSED_
#endif

#if defined(__WINDOWS_KERNEL_)
#define __MEMORY_BARRIER_()	KeMemoryBarrier()
#elif defined(__PLATFORM_WINDOWS_) && defined(__COMPILER_MSVC_)
#define __MEMORY_BARRIER_()	do { _ReadWriteBarrier(); _mm_mfence(); _ReadWriteBarrier(); } while (0)
#elif defined(__ARCH_ARM64_) && defined(__COMPILER_MSVC_)
#define __MEMORY_BARRIER_()	__dmb(_ARM64_BARRIER_SY)
#elif defined(__ARCH_ARM64_) && (defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_))
#define __MEMORY_BARRIER_()	__asm__ __volatile__("dmb sy" ::: "memory")
#elif (defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_)) && (defined(__ARCH_X64_) || defined(__ARCH_X86_))
#define __MEMORY_BARRIER_()	__asm__ __volatile__("mfence" ::: "memory")
#elif defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_)
#define __MEMORY_BARRIER_()	__sync_synchronize()
#else
#define __MEMORY_BARRIER_()	do { } while(0)
#endif

#if defined(__COMPILER_MSVC_)
#define __CDECL__		__cdecl
#define __STDCALL__		__stdcall
#define __VECTORCALL__	__vectorcall
#define __FASTCALL__	__fastcall
#define __THISCALL__	__thiscall
#else
#if defined(__COMPILER_CLANG_)
#define __VECTORCALL__	__attribute__((vectorcall))
#else
/* GCC doesnt support vector calls */
#define __VECTORCALL__
#endif
#if defined(__COMPILER_GCC_) && !defined(__ARCH_X86_)
#define __CDECL__
#define __STDCALL__
#define __FASTCALL__
#define __THISCALL__
#else
#define __CDECL__		__attribute__((cdecl))
#define __STDCALL__		__attribute__((stdcall))
#define __FASTCALL__	__attribute__((fastcall))
#define __THISCALL__	__attribute__((thiscall))
#endif
#define __MS_ABI__		__attribute__((ms_abi))
#define __SYSV_ABI__	__attribute__((sysv_abi))
#endif

namespace __RA
{
static __FORCE_INLINE_
bool __ra_tamper_allowed_cached(void) noexcept
{
#if !OBFUSCATOR_ENABLE_RA_TAMPER
	return false;
#endif
#if defined(__ARCH_ARM64_) && !OBFUSCATOR_ARM64_FORCE_TAMPER
	return false;
#endif
#if defined(__PLATFORM_WINDOWS_) && !defined(__WINDOWS_KERNEL_)
	using getpol_fn = BOOL (__STDCALL__*)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);

	static int cached = -1;
	if (cached >= 0) __LIKELY_
		return cached != 0;

	HMODULE k32 = GetModuleHandleW(L"kernel32.dll");

	PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY pol{};
	getpol_fn getpol;

	if (!k32) __UNLIKELY_
		goto __RA_FAIL;

	getpol = reinterpret_cast<getpol_fn>(
		GetProcAddress(k32, "GetProcessMitigationPolicy")
	);

	if (!getpol) __UNLIKELY_
		goto __RA_FAIL;

	if (!getpol(GetCurrentProcess(),
		ProcessUserShadowStackPolicy,
		&pol, sizeof(pol))) __UNLIKELY_
		goto __RA_FAIL;

	cached = pol.EnableUserShadowStack ? 0 : 1;
	return cached != 0;

__RA_FAIL:
	cached = 0;
	return false;
#else
	return true;
#endif
}
}

#if defined(__COMPILER_MSVC_)
#define __RETURN_ADDR_PTR_()	_AddressOfReturnAddress()
#elif defined(__COMPILER_CLANG_) || defined(__COMPILER_GCC_)
namespace __STACK_FRAGILE__
{
	__DEPRECATED_("Unstable and brittle check")
	static __FORCE_INLINE_
	int __probably_has_frame_ptr(volatile void** frame_ptr)
	{
		const uintptr_t fp = reinterpret_cast<uintptr_t>(frame_ptr);
		volatile uintptr_t sp;

#if defined(__ARCH_X64_)
		__asm__ __volatile__("movq %%rsp, %0" : "=r" (sp));
#elif defined(__ARCH_X86_)
		__asm__ __volatile__("movl %%esp, %0" : "=r" (sp));
#elif defined(__ARCH_ARM64_)
		__asm__ __volatile__("mov %0, sp" : "=r" (sp));
#else
#error "Unsupported architecture for return address pointer"
#endif
		/* Frame pointer should be above stack pointer, reasonable and aligned */
		return fp > sp && fp < sp + 0x100000 &&
			  (fp & (sizeof(void*) - 1)) == 0;
	}

	__DEPRECATED_("Compiler builtin is more reliable")
	static __FORCE_INLINE_
	void* __get_return_address_ptr(void)
	{
#if defined(_DEBUG) || defined(__DEBUG) || defined(__DEBUG__) \
					|| defined(DEBUG) && !defined(NDEBUG)
		static int checked = 0;
#endif
		volatile void** frame_ptr;
#if defined(__ARCH_X64_)
		__asm__ __volatile__("movq %%rbp, %0" : "=r" (frame_ptr));
#elif defined(__ARCH_X86_)
		__asm__ __volatile__("movl %%ebp, %0" : "=r" (frame_ptr));
#elif defined(__ARCH_ARM64_)
		__asm__ __volatile__("mov %0, x29" : "=r" (frame_ptr));
#else
#error "Unsupported architecture for return address pointer"
#endif
		if (!frame_ptr) __UNLIKELY_
			return nullptr;

#if defined(_DEBUG) || defined(__DEBUG) || defined(__DEBUG__) \
					|| defined(DEBUG) && !defined(NDEBUG)
		if (!checked)
		{
			/* -fno-omit-frame-pointer is no longer needed */
#if defined(__PLATFORM_LINUX_)
			if (!__STACK_FRAGILE__::__probably_has_frame_ptr(frame_ptr)) __UNLIKELY_
				static_cast<void>(write(
					STDERR_FILENO,
					"WARNING: Frame pointer appears invalid (-fno-omit-frame-pointer)\n",
					65 * sizeof(char)
				));
			checked = 1;
#endif
		}
#endif
		/* Return address is at [rbp+8] on 64-bit and [edp+4] on 32-bit */
		return reinterpret_cast<void*>(const_cast<void**>(frame_ptr + 1));
	}

	static __FORCE_INLINE_
	void* __get_return_address_ptr_new(void)
	{
		volatile void** frame_ptr = static_cast<volatile void**>(
										__builtin_frame_address(0));

		if (!frame_ptr) __UNLIKELY_
			return nullptr;

		/* Works for both 64 and 32 bit architectures:
		 * on 64-bit frame_ptr + 1 points to [rbp+8]
		 * on 32-bit frame_ptr + 1 points to [edp+4]
		 *
		 * The function is portable across architectures,
		 * adding 1 to frame_ptr results in 4 bytes
		 * on a 32-bit architecture, while on 64-bit
		 * adding 1 results in an 8 byte offset.
		 * This is because `+ 1` is `+ sizeof(void*)`
		 *
		 * Compiler builtin don't seem to really
		 * reproduce correct behavior, not sure
		 * why, maybe undefined behavior, but
		 * tests support this behavior:
		 * 
		 * Testing return address pointer functions...
		 * Main level:
		 *   Original:           0x7fffc13868c8
		 *   New:                0x7fffc13868c8
		 *   Match:              YES
		 *   Actual return addr: 0x6542453d0528
		 *   Pointed-to addr:    0x6542453d0528
		 *   Address valid:      YES
		 * 
		 * Level 1:
		 *   Original:           0x7fffc13868b8
		 *   New:                0x7fffc13868b8
		 *   Match:              YES
		 *   Actual return addr: 0x6542453d04dd
		 *   Pointed-to addr:    0x6542453d04dd
		 *   Address valid:      YES
		 * 
		 * Level 2:
		 *   Original:           0x7fffc13868b8
		 *   New:                0x7fffc13868b8
		 *   Match:              YES
		 *   Actual return addr: 0x6542453d04f2
		 *   Pointed-to addr:    0x6542453d04f2
		 *   Address valid:      YES
		 * 
		 * All tests passed!
		 *
		 * Important note:
		 * This behavior is not guaranteed when
		 * FPO/omit-frame-pointer is enabled,
		 * tail calls occur, or on AArch64 with
		 * aggressive prologues.
		 *
		 * Still, even with an omitted frame pointer
		 * it seems to work fine and consistently,
		 * the tests above were run without it.
		 *
		 * However, on AArch64 the link register (x30)
		 * might not be spilled on the stack at all
		 * for simple functions, even with a frame pointer.
		 * We still assume it's at [x29+8], but it might be
		 * incorrect. Since this pointer is being written
		 * to, special attention is required for this case.
		 *
		 * Ideally compile with:
		 *   -fno-omit-frame-pointer -fno-optimize-sibling-calls */

		return reinterpret_cast<void*>(const_cast<void**>(frame_ptr + 1));
	}
}

#define __RETURN_ADDR_PTR_() \
	__STACK_FRAGILE__::__get_return_address_ptr_new()

#endif

#if defined(__PLATFORM_LINUX_)
	typedef uint8_t		UINT8;
	typedef uint64_t	UINT64;
#endif

enum class CallingConvention : UINT8
{
	__CDECL,
#if defined(__PLATFORM_WINDOWS_)
	__STDCALL,
#endif
#if defined(__PLATFORM_WINDOWS_) && defined(_MANAGED)
	__CLRCALL,
#elif defined(__PLATFORM_WINDOWS_) && !defined(__COMPILER_GCC_) && !defined(_MANAGED)
	__VECTORCALL,
#endif
#if defined(__PLATFORM_WINDOWS_) && !defined(__ARCH_X64_) && !defined(__ARCH_ARM64_)
	__FASTCALL,
#endif
#if defined(__PLATFORM_WINDOWS_)
	__THISCALL,
#endif
#if defined(__PLATFORM_LINUX_)
	__MS_ABI,
#endif
#if defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_)
	__SYSV_ABI,
#endif
};

enum class ObfuscateStatus : UINT8
{
	SUCCEEDED,
	INITIALIZED,
	PENDING_CALL,
	INITIALIZED_TLS,
	UNINITIALIZED_TLS,
	INVALID_ENCRYPTION,
	INVALID_FUNCTION_ADDRESS,
	RA_TAMPER_NOT_ALLOWED,
	WEAK_ENCRYPTION_FALLBACK,
	CORRUPT_KEY_OR_STACK_ADDR,
	INVALID_CALLING_CONVENTION,
	UNINITIALIZED_STACK_CLEANUP,
};

#if defined(__WINDOWS_KERNEL_)
enum class LastThreadStatus : UINT8
{
	INIT_SUCCESS,
	INIT_FAILURE,
	THREAD_TERMINATED,
	THREAD_IS_CREATING,
	THREAD_IS_TERMINATING,
	UNINITIALIZED_GLOBAL
};
#endif

/* See the API section in README.md */

#define OBFUSCATE_FUNCTION	__StackObfuscator::detail::ObfuscateFunction \
								__obfuscate__(__RETURN_ADDR_PTR_())

/* Better practice to use the other macros instead. */
#define OBFUSCATE_CALL(ret_type, convention, name)		\
		(__StackObfuscator::detail::SafeCall<ret_type,	\
		convention, __StackObfuscator::detail::			\
		remove_reference_t<decltype(*name)>>(			\
		__StackObfuscator::detail::forward<				\
		decltype(name)>(name)))

#define OBFUSCATOR_LAST_STATE				__StackObfuscator::detail::__GET_LAST_STATE()

#define	OBFUSCATE_CDECL(ret, name)			OBFUSCATE_CALL(ret, CallingConvention::__CDECL,			name)
#if defined(__PLATFORM_WINDOWS_)
#define	OBFUSCATE_STDCALL(ret, name)		OBFUSCATE_CALL(ret, CallingConvention::__STDCALL,		name)
#endif
#if defined(__PLATFORM_WINDOWS_) && !defined(__ARCH_X64_) && !defined(__ARCH_ARM64_)
#define	OBFUSCATE_FASTCALL(ret, name)		OBFUSCATE_CALL(ret, CallingConvention::__FASTCALL,		name)
#endif
#if defined(__PLATFORM_WINDOWS_)
#define	OBFUSCATE_THISCALL(ret, name)		OBFUSCATE_CALL(ret, CallingConvention::__THISCALL,		name)
#endif
#if defined(__PLATFORM_WINDOWS_) && defined(_MANAGED)
#define	OBFUSCATE_CLRCALL(ret, name)		OBFUSCATE_CALL(ret, CallingConvention::__CLRCALL,		name)
#elif defined(__PLATFORM_WINDOWS_) && !defined(__COMPILER_GCC_) && !defined(_MANAGED)
#define	OBFUSCATE_VECTORCALL(ret, name)		OBFUSCATE_CALL(ret, CallingConvention::__VECTORCALL,	name)
#endif
#if defined(__PLATFORM_LINUX_) && !defined(__COMPILER_MSVC_)
#define OBFUSCATE_MICROSOFT_ABI(ret, name)	OBFUSCATE_CALL(ret, CallingConvention::__MS_ABI,		name)
#endif
#if defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_)
#define OBFUSCATE_LINUX_ABI(ret, name)		OBFUSCATE_CALL(ret, CallingConvention::__SYSV_ABI,		name)
#endif

#define __KEY_USES_ROTATION_DEFAULT 32

#if !defined(__WINDOWS_KERNEL_)
/* Number of obfuscation uses before key rotation (consider performance when adjusting) */
#define OBFUSCATOR_KEY_USES_BEFORE_ROTATION __StackObfuscator::detail::key_uses_before_rotation
#endif

#if defined(__WINDOWS_KERNEL_)
/* These need to be called very early: Ideally DriverEntry() */
#define REGISTER_OBFUSCATOR_THREAD_RESOURCE_MANAGEMENT		__StackObfuscator::detail::__RegisterThreadCleanup()
#define UNREGISTER_OBFUSCATOR_THREAD_RESOURCE_MANAGEMENT	__StackObfuscator::detail::__UnregisterThreadCleanup()
#define LAST_THREAD_STATE									__StackObfuscator::detail::__LAST_THREAD_STATE
#endif

/* Avoid using the implementation directly */
namespace __StackObfuscator
{
	inline namespace detail
	{
#if !defined(__WINDOWS_KERNEL_)
	static inline int thread_local key_uses_before_rotation = __KEY_USES_ROTATION_DEFAULT;
	static inline ObfuscateStatus thread_local __LAST_STATE = ObfuscateStatus::INITIALIZED;

	__FORCE_INLINE_
	void __SET_LAST_STATE(ObfuscateStatus status) noexcept
	{
		__LAST_STATE = status;
	}

	__FORCE_INLINE_
	ObfuscateStatus __GET_LAST_STATE(void) noexcept
	{
		return __LAST_STATE;
	}
#else
	typedef UINT64 uintptr_t;

	LastThreadStatus __LAST_THREAD_STATE = LastThreadStatus::UNINITIALIZED_GLOBAL;

	/* Important kernel mode memory alignment */
	struct DECLSPEC_ALIGN(64) ThreadState
	{
		UINT64				s[4];			/* Key related data		*/
		UINT64				current_key;	/* Thread local key		*/
		BOOLEAN				initialized;	/* Thread init state	*/
		::ObfuscateStatus	last_state;		/* Last internal state	*/
		UINT32				max_key_uses;	/* Maximum key uses     */
		UINT32				key_uses;		/* Encryption key uses  */
	};

	namespace __ThreadLocal
	{

	constexpr const ULONG TLS_BUCKETS = 64;

	struct StateNode
	{
		PKTHREAD	thread;
		ThreadState	state;
		StateNode*	next;
	};

	struct alignas(64) Bucket
	{
		KSPIN_LOCK	lock;
		StateNode*	head;
	};

	static Bucket			g_tlsBuckets[TLS_BUCKETS];
	static volatile LONG	g_tlsBucketsInit = 0;

	__FORCE_INLINE_
	ULONG ptr_hash(PVOID p) noexcept
	{
		const UINT64 x = (UINT64)(ULONG_PTR)p;
		UINT64 h = x ^ (x >> 33);
		h *= 0xff51afd7ed558ccdULL;
		h ^= h >> 33;
		return (ULONG)(h & (TLS_BUCKETS - 1));
	}

	__FORCE_INLINE_
	void __InitKernelTlsBuckets(void) noexcept
	{
		for (ULONG i = 0; i < TLS_BUCKETS; ++i)
		{
			KeInitializeSpinLock(&g_tlsBuckets[i].lock);
			g_tlsBuckets[i].head = nullptr;
		}
	}

	__FORCE_INLINE_
	void __FreeThreadState(PKTHREAD th) noexcept
	{
		auto& b = g_tlsBuckets[ptr_hash(th)];

		KIRQL oldIrql;
		KeAcquireSpinLock(&b.lock, &oldIrql);

		StateNode** prev	= &b.head;
		StateNode*  victim	= nullptr;

		for (StateNode* n = b.head; n; n = n->next)
		{
			if (n->thread == th)
			{
				*prev  = n->next;
				victim = n;
				break;
			}
			prev = &n->next;
		}

		KeReleaseSpinLock(&b.lock, oldIrql);

		if (victim) __LIKELY_
		{
			RtlSecureZeroMemory(&victim->state, sizeof(victim->state));
			ExFreePoolWithTag(victim, 'SfBO');
		}
	}

	__FORCE_INLINE_
	void __PurgeAllThreadStates(void) noexcept
	{
		for (ULONG i = 0; i < TLS_BUCKETS; ++i)
		{
			auto& b = g_tlsBuckets[i];

			KIRQL oldIrql;
			KeAcquireSpinLock(&b.lock, &oldIrql);

			StateNode* list	= b.head;
			b.head			= nullptr;

			KeReleaseSpinLock(&b.lock, oldIrql);

			while (list)
			{
				StateNode* next = list->next;

				RtlSecureZeroMemory(&list->state, sizeof(list->state));
				ExFreePoolWithTag(list, 'SfBO');

				list = next;
			}
		}
	}
	}

	__FORCE_INLINE_
	ThreadState* getThreadState(void) noexcept
	{
		if (!__ThreadLocal::g_tlsBucketsInit) __UNLIKELY_
			if (!InterlockedCompareExchange(&__ThreadLocal::g_tlsBucketsInit, 1, 0)) __LIKELY_
				__ThreadLocal::__InitKernelTlsBuckets();

		PKTHREAD th	= KeGetCurrentThread();
		auto& b		= __ThreadLocal::g_tlsBuckets[__ThreadLocal::ptr_hash(th)];

		KIRQL oldIrql;
		KeAcquireSpinLock(&b.lock, &oldIrql);

		for (__ThreadLocal::StateNode* n = b.head; n; n = n->next)
		{
			if (n->thread == th)
			{
				KeReleaseSpinLock(&b.lock, oldIrql);
				return &n->state;
			}
		}

		KeReleaseSpinLock(&b.lock, oldIrql);

		__ThreadLocal::StateNode* fresh = (__ThreadLocal::StateNode*)ExAllocatePoolZero(
			NonPagedPoolNx, sizeof(__ThreadLocal::StateNode), 'SfBO'
		);

		if (!fresh) __UNLIKELY_
			return nullptr;

		fresh->thread				= th;
		fresh->state.initialized	= FALSE;
		fresh->state.key_uses		= 0;
		fresh->state.max_key_uses	= __KEY_USES_ROTATION_DEFAULT;
		fresh->state.last_state		= ObfuscateStatus::INITIALIZED_TLS;

		KeyGenerator::initThreadStateKey(&fresh->state);
		fresh->state.initialized	= TRUE;

		KeAcquireSpinLock(&b.lock, &oldIrql);
		for (__ThreadLocal::StateNode* n = b.head; n; n = n->next)
		{
			if (n->thread == th)
			{
				ThreadState* s = &n->state;
				KeReleaseSpinLock(&b.lock, oldIrql);
				RtlSecureZeroMemory(&fresh->state, sizeof(fresh->state));
				ExFreePoolWithTag(fresh, 'SfBO');
				return s;
			}
		}

		fresh->next	= b.head;
		b.head		= fresh;

		KeReleaseSpinLock(&b.lock, oldIrql);
		return &fresh->state;
	}

	__FORCE_INLINE_
	void __SET_LAST_STATE(ObfuscateStatus status) noexcept
	{
		ThreadState* state = getThreadState();

		if (!state) __UNLIKELY_
			return;

		state->last_state = status;
	}

	__FORCE_INLINE_
	ObfuscateStatus __GET_LAST_STATE(void) noexcept
	{
		ThreadState* state = getThreadState();

		if (!state) __UNLIKELY_
			return ObfuscateStatus::UNINITIALIZED_TLS;

		return state->last_state;
	}
#endif
	template <class _Ty>
	struct remove_reference
	{
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_reference<_Ty&>
	{
		using type = _Ty;
	};

	template <class _Ty>
	struct remove_reference<_Ty&&>
	{
		using type = _Ty;
	};

	template <class _Ty>
	using remove_reference_t = typename remove_reference<_Ty>::type;

	template <class>
	inline constexpr bool is_lvalue_reference_v = false;

	template <class _Ty>
	inline constexpr bool is_lvalue_reference_v<_Ty&> = true;

	template <class _Ty>
	constexpr _Ty&& forward(remove_reference_t<_Ty>& _Arg) noexcept
	{
		return static_cast<_Ty&&>(_Arg);
	}

	template <class _Ty>
	constexpr _Ty&& forward(remove_reference_t<_Ty>&& _Arg) noexcept
	{
		static_assert(
			!detail::is_lvalue_reference_v<_Ty>,
			"Cannot forward an lvalue reference"
		);
		return static_cast<_Ty&&>(_Arg);
	}

	template <typename T, typename U>
	static constexpr bool is_same = false;

	template <typename T>
	static constexpr bool is_same<T, T> = true;

#if !defined(__WINDOWS_KERNEL_)

	template <typename> struct __fn_sig;
	template <typename R, typename... P>
	struct __fn_sig<R(P...)>
	{
		using ret	 = R;
		using params = std::tuple<P...>;
	};

	template <typename Tp>
	using __tuple_index_seq = std::make_index_sequence<std::tuple_size_v<Tp>>;

#if defined(__COMPILER_MSVC_)
	template <typename R, typename... P> using __cdecl_ptr_t		= R(__CDECL__		*)(P...);
	template <typename R, typename... P> using __stdcall_ptr_t		= R(__STDCALL__		*)(P...);
	template <typename R, typename... P> using __vectorcall_ptr_t	= R(__VECTORCALL__	*)(P...);
	template <typename R, typename... P> using __fastcall_ptr_t		= R(__FASTCALL__	*)(P...);
	template <typename R, typename... P> using __thiscall_ptr_t		= R(__THISCALL__	*)(P...);

	template <CallingConvention CC, typename R, typename Tp> struct __rebind_fnptr;

	template <typename R, typename... P>
	struct __rebind_fnptr<CallingConvention::__CDECL, R, std::tuple<P...>>
	{
		using type = __cdecl_ptr_t<R, P...>;
	};

#if defined(__PLATFORM_WINDOWS_)
	template <typename R, typename... P>
	struct __rebind_fnptr<CallingConvention::__STDCALL, R, std::tuple<P...>>
	{
		using type = __stdcall_ptr_t<R, P...>; 
	};

	template <typename R, typename... P>
	struct __rebind_fnptr<CallingConvention::__THISCALL, R, std::tuple<P...>>
	{
		using type = __thiscall_ptr_t<R, P...>; 
	};

#if !defined(_MANAGED)
	template <typename R, typename... P>
	struct __rebind_fnptr<CallingConvention::__VECTORCALL, R, std::tuple<P...>>
	{
		using type = __vectorcall_ptr_t<R, P...>; 
	};
#endif

#if defined(__ARCH_X86_)
	template <typename R, typename... P>
	struct __rebind_fnptr<CallingConvention::__FASTCALL, R, std::tuple<P...>>
	{
		using type = __fastcall_ptr_t<R, P...>; 
	};
#endif

#endif
#endif

	template <typename Fn, typename Tp, std::size_t... I, typename... A>
	__FORCE_INLINE_
	auto __invoke_declared(Fn&& fn, std::index_sequence<I...>, A&&... a)
		noexcept(noexcept(std::forward<Fn>(fn)(static_cast<std::tuple_element_t<I, Tp>>(detail::forward<A>(a))...)))
		-> decltype(fn(static_cast<std::tuple_element_t<I, Tp>>(detail::forward<A>(a))...))
	{
		static_assert(std::tuple_size_v<Tp> == sizeof...(I), "Index pack must match tuple arity");
		return detail::forward<Fn>(fn)(static_cast<std::tuple_element_t<I, Tp>>(detail::forward<A>(a))...);
	}

#else

template <typename> struct __km_sig;

template <typename R, typename... P>
struct __km_sig<R(P...)>
{
	using ret = R;

	template <typename Fn, typename... A>
	static __FORCE_INLINE_
	R invoke(Fn fn, A&&... a) noexcept
	{
		return fn(static_cast<P>(detail::forward<A>(a))...);
	}
};

template <CallingConvention CC, typename Sig> struct __km_rebind;

template <typename R, typename... P>
struct __km_rebind<CallingConvention::__CDECL, R(P...)>
{
	using type = R(__CDECL__*)(P...);
};

template <typename R, typename... P>
struct __km_rebind<CallingConvention::__STDCALL, R(P...)>
{
	using type = R(__STDCALL__*)(P...);
};

template <typename R, typename... P>
struct __km_rebind<CallingConvention::__THISCALL, R(P...)>
{
	using type = R(__THISCALL__*)(P...);
};

#if !defined(_MANAGED)
template <typename R, typename... P>
struct __km_rebind<CallingConvention::__VECTORCALL, R(P...)>
{
	using type = R(__VECTORCALL__*)(P...);
};
#endif

#if defined(__ARCH_X86_)
template <typename R, typename... P>
struct __km_rebind<CallingConvention::__FASTCALL, R(P...)>
{
	using type = R(__FASTCALL__*)(P...);
};
#endif

#endif

	/* Encryption is done manually in kernel mode due to lack of STL
	 * Using xoshiro256 encryption implementation for fast generation,
	 * good statistical properties and suitable for cryptographic keys. */

	class KeyGenerator
	{
	private:
#if defined(__WINDOWS_KERNEL_)
		static __FORCE_INLINE_
		UINT64 rotl(const UINT64 x, int k) noexcept
		{
			return (x << k) | (x >> (64 - k));
		}

		static __FORCE_INLINE_
		void addEntropy(ThreadState* state) noexcept
		{
			if (!state)
				return;

			state->s[0] ^= __rdtsc();
			state->s[1] ^= KeQueryPerformanceCounter(nullptr).QuadPart;
		}

		static __FORCE_INLINE_
		UINT64 next(ThreadState* __RESTRICT_ state) noexcept
		{
			const UINT64 result	= rotl(state->s[1] * 5, 7) * 9;
			const UINT64 t		= state->s[1] << 17;

			state->s[2] ^= state->s[0];
			state->s[3] ^= state->s[1];
			state->s[1] ^= state->s[2];
			state->s[0] ^= state->s[3];

			state->s[2] ^= t;
			state->s[3] = rotl(state->s[3], 45);

			addEntropy(state);

			return result;
		}

		static __FORCE_INLINE_
		void generateNewKey(ThreadState* __RESTRICT_ state) noexcept
		{
			constexpr const int MAX_ATTEMPTS = 100;
			int attempts = 0;

			do
			{
				for (int i = 0; i < 4; ++i)
					next(state);

				state->current_key = next(state);
				++attempts;
			}	while (!__verify_entropy_quality(state->current_key)
						&& attempts < MAX_ATTEMPTS);

			__MEMORY_BARRIER_();
			
			if (!__verify_entropy_quality(state->current_key)) __UNLIKELY_
			{
				state->current_key = next(state) ^ __rdtsc() ^ (UINT64)state;
				__SET_LAST_STATE(ObfuscateStatus::WEAK_ENCRYPTION_FALLBACK);
			}
		}
#else
		using distribution = std::uniform_int_distribution<uintptr_t>;

		static inline thread_local uintptr_t		current_key;
		static inline thread_local bool				initialized;
		static inline thread_local std::mt19937_64	thread_gen;
		static inline thread_local distribution		thread_dis;

		static __FORCE_INLINE_
		void initThreadLocal(void) noexcept
		{
			if (initialized) __UNLIKELY_
				return;

			std::random_device rd;
			thread_gen.seed(rd());
			__MEMORY_BARRIER_();
			initialized = true;
		}
#endif
		static __FORCE_INLINE_
		bool __verify_entropy_quality(UINT64 key) noexcept
		{
			if (!key) __UNLIKELY_
				return false;

			UINT8 first_byte = (UINT8)(key & 0xFF);
			bool all_same = true;
			for (int i = 1; i < 8; ++i)
			{
				if (((key >> (i * 8)) & 0XFF) != first_byte)
				{
					all_same = false;
					break;
				}
			}

			if (all_same) __UNLIKELY_
				return false;

			/* Used to be `20 <= popcnt <= 44`,
			 * but in an effort to reduce
			 * MAX_ATTEMPTS pressure, I lowered
			 * the bounds to 16 and 48.
			 * with 20 and 44, it would reject
			 * ~90% of uniformly random keys,
			 * which caused many retries. */

#if defined(__COMPILER_MSVC_)
			const auto popcount = __popcnt64(key);
			return popcount >= 16 && popcount <= 48;
#else
#if defined(__has_builtin) && __has_builtin(__builtin_popcountll)
			const auto popcount = __builtin_popcountll(key);
			return popcount >= 16 && popcount <= 48;
#else
			/* For old CPUs without popcount: 
			 * check if upper and lower
			 * halves are different */
			uint32_t upper = (uint32_t)(key >> 32);
			uint32_t lower = (uint32_t)(key & 0xFFFFFFFF);
			
			if (upper == lower) __UNLIKELY_
				return false;

			if (upper == lower + 1 || upper == lower - 1) __UNLIKELY_
				return false;
				
			__SET_LAST_STATE(ObfuscateStatus::WEAK_ENCRYPTION_FALLBACK);

			return true;
#endif
#endif
		}
	public:
#if defined(__WINDOWS_KERNEL_)
		static __FORCE_INLINE_
		void initThreadStateKey(ThreadState* __RESTRICT_ state) noexcept
		{
			if (state->initialized) __UNLIKELY_
				return;

			LARGE_INTEGER time;
			KeQuerySystemTime(&time);

			state->s[0] = time.QuadPart;
			state->s[1] = __rdtsc();
			state->s[2] = (UINT64)PsGetCurrentProcess();
			state->s[3] = (UINT64)PsGetCurrentThread();

			__MEMORY_BARRIER_();

			constexpr const int KEY_GEN_ROUNDS = 32;
			for (int i = 0; i < KEY_GEN_ROUNDS; ++i)
				next(state);

			__MEMORY_BARRIER_();

			generateNewKey(state);
		}

		static __FORCE_INLINE_
		UINT64 getKey(void) noexcept
		{
			ThreadState* state = getThreadState();

			if (!state) __UNLIKELY_
				return 0;

			if (state->key_uses >= state->max_key_uses) __UNLIKELY_
			{
				generateNewKey(state);
				state->key_uses = 0;
			}

			++state->key_uses;

			return state->current_key;
		}
#else
		static __FORCE_INLINE_
		uintptr_t getKey(void) noexcept
		{
			static thread_local int __uses = 0;

			if (__uses >= key_uses_before_rotation) __UNLIKELY_
			{
				__uses = 0;
				current_key = 0;
			}

			if (current_key) __LIKELY_
			{
				++__uses;
				return current_key;
			}

			initThreadLocal();

			constexpr const int MAX_ATTEMPTS = 100;
			int attempts = 0;

			do
			{
				current_key = thread_dis(thread_gen);
				++attempts;
			}	while (!__verify_entropy_quality(current_key)
						&& attempts < MAX_ATTEMPTS);

			__MEMORY_BARRIER_();
			
			if (!__verify_entropy_quality(current_key))
			{
				current_key = thread_dis(thread_gen);
				__SET_LAST_STATE(ObfuscateStatus::WEAK_ENCRYPTION_FALLBACK);
			}

			++__uses;

			return current_key;
		}
#endif
	};

#if defined(__WINDOWS_KERNEL_)
	VOID __ThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) noexcept
	{
		UNREFERENCED_PARAMETER(ProcessId);
		UNREFERENCED_PARAMETER(ThreadId);

		if (Create)
		{
			__LAST_THREAD_STATE = LastThreadStatus::THREAD_IS_CREATING;
			/* Lazy initialization, doing it here is cheap */
			(void)getThreadState();
		}
		else
		{
			__ThreadLocal::__FreeThreadState(KeGetCurrentThread());
			__LAST_THREAD_STATE = LastThreadStatus::THREAD_TERMINATED;
		}
	}

	__FORCE_INLINE_
	NTSTATUS __RegisterThreadCleanup(void) noexcept
	{
		__ThreadLocal::__InitKernelTlsBuckets();
		return PsSetCreateThreadNotifyRoutine(__ThreadNotifyCallback);
	}

	__FORCE_INLINE_
	NTSTATUS __UnregisterThreadCleanup(void) noexcept
	{
		const NTSTATUS st = PsRemoveCreateThreadNotifyRoutine(__ThreadNotifyCallback);
		__ThreadLocal::__PurgeAllThreadStates();
		return st;
	}
#endif

	/* Doesn't protect against value manipulation */
	static __FORCE_INLINE_
	void __verify_return_addr(void* addr)
	{
		/* We know the addr should never be 0x0 */
		if (!addr) __UNLIKELY_
		{
			__SET_LAST_STATE(ObfuscateStatus::CORRUPT_KEY_OR_STACK_ADDR);
#if defined(__WINDOWS_KERNEL_)
			KeBugCheckEx(
				CRITICAL_STRUCTURE_CORRUPTION,
				(ULONG_PTR)_ReturnAddress(),
				(ULONG_PTR)0xC0000000,
				(ULONG_PTR)addr, 0
			);
#elif defined(__PLATFORM_WINDOWS_)
			__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE);
#elif defined(__PLATFORM_LINUX_)
			kill(getpid(), SIGKILL);
			__builtin_unreachable();
#endif
		}
	}

	class __NO_SCS_ ObfuscateFunction
	{
	private:
		const uintptr_t		xor_key;
		volatile uintptr_t*	ra_slot		= nullptr;
		bool				initialized	= false;
		uintptr_t			tmp			= 0;

	public:
		__NO_CFG_ __FORCE_INLINE_
		ObfuscateFunction(void* ret_addr) noexcept
			: xor_key(KeyGenerator::getKey())
		{
			if (!ret_addr) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_FUNCTION_ADDRESS);
				return;
			}

			if (!xor_key) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);
				return;
			}

			if (!__RA::__ra_tamper_allowed_cached()) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}

			ra_slot = reinterpret_cast<volatile uintptr_t*>(ret_addr);

			tmp = *ra_slot ^ xor_key;
			__MEMORY_BARRIER_();
			*ra_slot = 0;

			initialized = true;
			__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
		}

		__NO_CFG_ __FORCE_INLINE_
		~ObfuscateFunction(void) noexcept
		{
			if (!initialized) __UNLIKELY_
			{
				ObfuscateStatus status = __GET_LAST_STATE();

				if (status != ObfuscateStatus::INVALID_FUNCTION_ADDRESS &&
					status != ObfuscateStatus::INVALID_ENCRYPTION) __UNLIKELY_
					__SET_LAST_STATE(ObfuscateStatus::UNINITIALIZED_STACK_CLEANUP);

				return;
			}

			if (!__RA::__ra_tamper_allowed_cached()) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}

			if (!xor_key) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);
				return;
			}

			*ra_slot = tmp ^ xor_key;

			__MEMORY_BARRIER_();
			__verify_return_addr(const_cast<void*>(
				reinterpret_cast<volatile void*>(ra_slot))
			);

			__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
		}
	};

	template <CallingConvention cc, typename RetType, typename Callable, typename... Args>
	__NO_CFG_ __NO_SCS_ __NO_STACK_PROTECT_
	RetType ShellCodeManager(Callable* f, Args&&... args) noexcept
	{
		static_assert(!detail::is_same<Callable, void>,
			"Callable must be a real function type, did you pass a void* generic?"
		);

		OBFUSCATE_FUNCTION;

		const uintptr_t	xor_key = KeyGenerator::getKey();

		if (!xor_key) __UNLIKELY_
		{
			__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);

			if constexpr (detail::is_same<RetType, void>)
				return;

			return RetType();
		}

		void* ret_addr = nullptr;
		uintptr_t tmp  = 0;

		bool ra_allowed = __RA::__ra_tamper_allowed_cached();

		if (ra_allowed) __LIKELY_
		{
			ret_addr = __RETURN_ADDR_PTR_();
			if (ret_addr) __LIKELY_
			{
				auto* ra = reinterpret_cast<volatile uintptr_t*>(ret_addr);
				__MEMORY_BARRIER_();
				tmp = *ra ^ xor_key;
				__MEMORY_BARRIER_();
				*ra = 0;
			}
			else
				ra_allowed = false;
		}

		struct __restore_t
		{
			volatile uintptr_t*	ra_slot;
			uintptr_t			tmp;
			uintptr_t			xor_key;
			bool				ra_allowed;

			__FORCE_INLINE_ __NO_SCS_
			void operator()() const noexcept
			{
				if (!ra_allowed || !ra_slot) __UNLIKELY_
					return;

				*ra_slot = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(const_cast<void*>(
					reinterpret_cast<volatile void*>(ra_slot))
				);
			}
		};

		volatile uintptr_t* ra_slot = ra_allowed && ret_addr
			? reinterpret_cast<volatile uintptr_t*>(ret_addr)
			: nullptr;

		__MAYBE_UNUSED_ __restore_t __restore{ ra_slot, tmp, xor_key, ra_allowed };

		/* The purpose of the restructuring is to keep the callee's true prototype when calling.
		 *
		 * Historically this code did this:
		 *     auto function = reinterpret_cast<Ret(__CDECL__*)(remove_reference_t<Args>...)>(f);
		 * which rebuilds a prototype from the call-site argument types (Args...).
		 *
		 * The old approach was incorrect and could've been undefined behavior:
		 *   - The rebuilt signature may not match the real function's signature
		 *   due to scalars. (e.g. size_t vs int, const void* vs const char*, etc.).
		 *   - This results in a warning: -Wcast-function-type because the cast
		 *   lies about the function type and calling convention.
		 *   - Even if the ABI happens to pass the same bits, it is not guaranteed.
		 *
		 * Therefore, I now instead made it to preserve the original function type
		 * so the call is performed with the actual prototype. Then normal C++
		 * conversions apply at the call-site (e.g., int->size_t, const char[N] -> const char*,
		 * and const void* where needed) without any undefined behavior or warnings.
		 *
		 * On GCC/Clang we therefore avoid any reinterpret_cast and maintain the
		 * exact pointer type, which removes warnings and is ABI safe.
		 *
		 * On MSVC, calling conventions are encoded in the type. To ensure the intended
		 * Calling convention is stamped into the pointer type, we rebind the function
		 * pointer by type, not by call-site argument deduction. That keeps real parameter
		 * and return types while adding the desired calling convention to the type.
		 *
		 * When I originally made this, I intended to do this, but I could not for the
		 * life of me figure out how. There was nothing online that I could find at the time,
		 * and I was not advanced enough in the language to figure it out. I had tried many
		 * approaches, but in the end I wasn't able, and kept the undefined behavior approach
		 * since if we used the correct ABI macro, the undefined behavior proved reliable and
		 * consistent. And while in practice that would always work to be fair, this is better. */

		if constexpr (cc == CallingConvention::__CDECL)
		{
#if defined(__WINDOWS_KERNEL_)
			using traits	= __km_sig<Callable>;
			using Ret		= typename traits::ret;

			using fnptr_t	= typename __km_rebind<CallingConvention::__CDECL, Callable>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			using traits	= __fn_sig<Callable>;
			using Ret		= typename traits::ret;
#if defined(__COMPILER_MSVC_)
			using Params	= typename traits::params;
			using fnptr_t	= typename __rebind_fnptr<CallingConvention::__CDECL, Ret, Params>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			auto function	= f;
#endif
#endif
			if constexpr (detail::is_same<Ret, void>)
			{
#if defined(__WINDOWS_KERNEL_)
				traits::invoke(function, detail::forward<Args>(args)...);
#else
				function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}
			else
			{
#if defined(__WINDOWS_KERNEL_)
				Ret ret = traits::invoke(function, detail::forward<Args>(args)...);
#else
				Ret ret = function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return ret;
			}
		}
#if defined(__PLATFORM_WINDOWS_)
		else if constexpr (cc == CallingConvention::__STDCALL)
		{
#if defined(__WINDOWS_KERNEL_)
			using traits	= __km_sig<Callable>;
			using Ret		= typename traits::ret;

			using fnptr_t	= typename __km_rebind<CallingConvention::__STDCALL, Callable>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			using traits	= __fn_sig<Callable>;
			using Ret		= typename traits::ret;
#if defined(__COMPILER_MSVC_)
			using Params	= typename traits::params;
			using fnptr_t	= typename __rebind_fnptr<CallingConvention::__STDCALL, Ret, Params>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			auto function	= f;
#endif
#endif
			if constexpr (detail::is_same<Ret, void>)
			{
#if defined(__WINDOWS_KERNEL_)
				traits::invoke(function, detail::forward<Args>(args)...);
#else
				function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}
			else
			{
#if defined(__WINDOWS_KERNEL_)
				Ret ret = traits::invoke(function, detail::forward<Args>(args)...);
#else
				Ret ret = function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return ret;
			}
		}
#endif
#if defined(__PLATFORM_WINDOWS_) && defined(_MANAGED)
		else if constexpr (cc == CallingConvention::__CLRCALL)
		{
#if defined(__WINDOWS_KERNEL_)
			using traits	= __km_sig<Callable>;
			using Ret		= typename traits::ret;

			using fnptr_t	= typename __km_rebind<CallingConvention::__CLRCALL, Callable>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			using traits	= __fn_sig<Callable>;
			using Ret		= typename traits::ret;
#if defined(__COMPILER_MSVC_)
			using Params	= typename traits::params;
			using fnptr_t	= typename __rebind_fnptr<CallingConvention::__CLRCALL, Ret, Params>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			auto function	= f;
#endif
#endif
			if constexpr (detail::is_same<Ret, void>)
			{
#if defined(__WINDOWS_KERNEL_)
				traits::invoke(function, detail::forward<Args>(args)...);
#else
				function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}
			else
			{
#if defined(__WINDOWS_KERNEL_)
				Ret ret = traits::invoke(function, detail::forward<Args>(args)...);
#else
				Ret ret = function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return ret;
			}
		}
#elif defined(__PLATFORM_WINDOWS_) && !defined(__COMPILER_GCC_) && !defined(_MANAGED)
		else if constexpr (cc == CallingConvention::__VECTORCALL)
		{
#if defined(__WINDOWS_KERNEL_)
			using traits	= __km_sig<Callable>;
			using Ret		= typename traits::ret;

			using fnptr_t	= typename __km_rebind<CallingConvention::__VECTORCALL, Callable>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			using traits	= __fn_sig<Callable>;
			using Ret		= typename traits::ret;
#if defined(__COMPILER_MSVC_)
			using Params	= typename traits::params;
			using fnptr_t	= typename __rebind_fnptr<CallingConvention::__VECTORCALL, Ret, Params>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			auto function	= f;
#endif
#endif
			if constexpr (detail::is_same<Ret, void>)
			{
#if defined(__WINDOWS_KERNEL_)
				traits::invoke(function, detail::forward<Args>(args)...);
#else
				function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}
			else
			{
#if defined(__WINDOWS_KERNEL_)
				Ret ret = traits::invoke(function, detail::forward<Args>(args)...);
#else
				Ret ret = function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return ret;
			}
		}
#endif
#if defined(__PLATFORM_WINDOWS_) && !defined(__ARCH_X64_) && !defined(__ARCH_ARM64_)
		else if constexpr (cc == CallingConvention::__FASTCALL)
		{
#if defined(__WINDOWS_KERNEL_)
			using traits	= __km_sig<Callable>;
			using Ret		= typename traits::ret;

			using fnptr_t	= typename __km_rebind<CallingConvention::__FASTCALL, Callable>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			using traits	= __fn_sig<Callable>;
			using Ret		= typename traits::ret;
#if defined(__COMPILER_MSVC_)
			using Params	= typename traits::params;
			using fnptr_t	= typename __rebind_fnptr<CallingConvention::__FASTCALL, Ret, Params>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			auto function	= f;
#endif
#endif
			if constexpr (detail::is_same<Ret, void>)
			{
#if defined(__WINDOWS_KERNEL_)
				traits::invoke(function, detail::forward<Args>(args)...);
#else
				function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}
			else
			{
#if defined(__WINDOWS_KERNEL_)
				Ret ret = traits::invoke(function, detail::forward<Args>(args)...);
#else
				Ret ret = function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return ret;
			}
		}
#endif
#if defined(__PLATFORM_WINDOWS_)
		else if constexpr (cc == CallingConvention::__THISCALL)
		{
#if defined(__WINDOWS_KERNEL_)
			using traits	= __km_sig<Callable>;
			using Ret		= typename traits::ret;

			using fnptr_t	= typename __km_rebind<CallingConvention::__THISCALL, Callable>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			using traits	= __fn_sig<Callable>;
			using Ret		= typename traits::ret;
#if defined(__COMPILER_MSVC_)
			using Params	= typename traits::params;
			using fnptr_t	= typename __rebind_fnptr<CallingConvention::__THISCALL, Ret, Params>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			auto function	= f;
#endif
#endif
			if constexpr (detail::is_same<Ret, void>)
			{
#if defined(__WINDOWS_KERNEL_)
				traits::invoke(function, detail::forward<Args>(args)...);
#else
				function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}
			else
			{
#if defined(__WINDOWS_KERNEL_)
				Ret ret = traits::invoke(function, detail::forward<Args>(args)...);
#else
				Ret ret = function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return ret;
			}
		}
#endif
#if defined(__PLATFORM_LINUX_) && !defined(__COMPILER_MSVC_)
		else if constexpr (cc == CallingConvention::__MS_ABI)
		{
#if defined(__WINDOWS_KERNEL_)
			using traits	= __km_sig<Callable>;
			using Ret		= typename traits::ret;

			using fnptr_t	= typename __km_rebind<CallingConvention::__MS_ABI, Callable>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			using traits	= __fn_sig<Callable>;
			using Ret		= typename traits::ret;
#if defined(__COMPILER_MSVC_)
			using Params	= typename traits::params;
			using fnptr_t	= typename __rebind_fnptr<CallingConvention::__MS_ABI, Ret, Params>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			auto function	= f;
#endif
#endif
			if constexpr (detail::is_same<Ret, void>)
			{
#if defined(__WINDOWS_KERNEL_)
				traits::invoke(function, detail::forward<Args>(args)...);
#else
				function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}
			else
			{
#if defined(__WINDOWS_KERNEL_)
				Ret ret = traits::invoke(function, detail::forward<Args>(args)...);
#else
				Ret ret = function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return ret;
			}
		}
#endif
#if defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_)
		else if constexpr (cc == CallingConvention::__SYSV_ABI)
		{
#if defined(__WINDOWS_KERNEL_)
			using traits	= __km_sig<Callable>;
			using Ret		= typename traits::ret;

			using fnptr_t	= typename __km_rebind<CallingConvention::__SYSV_ABI, Callable>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			using traits	= __fn_sig<Callable>;
			using Ret		= typename traits::ret;
#if defined(__COMPILER_MSVC_)
			using Params	= typename traits::params;
			using fnptr_t	= typename __rebind_fnptr<CallingConvention::__SYSV_ABI, Ret, Params>::type;
			auto function	= reinterpret_cast<fnptr_t>(f);
#else
			auto function	= f;
#endif
#endif
			if constexpr (detail::is_same<Ret, void>)
			{
#if defined(__WINDOWS_KERNEL_)
				traits::invoke(function, detail::forward<Args>(args)...);
#else
				function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return;
			}
			else
			{
#if defined(__WINDOWS_KERNEL_)
				Ret ret = traits::invoke(function, detail::forward<Args>(args)...);
#else
				Ret ret = function(detail::forward<Args>(args)...);
#endif
				__MEMORY_BARRIER_();
				__restore();
				__SET_LAST_STATE(ra_allowed ? ObfuscateStatus::SUCCEEDED
											: ObfuscateStatus::RA_TAMPER_NOT_ALLOWED);
				return ret;
			}
		}
#endif

		__SET_LAST_STATE(ObfuscateStatus::INVALID_CALLING_CONVENTION);

		__MEMORY_BARRIER_();
		__restore();

		if constexpr (!detail::is_same<RetType, void>)
			return RetType();
	}

	template<typename RetType, CallingConvention cc, class Callable>
	class SafeCall
	{
	private:
		Callable* f;

	public:
		__FORCE_INLINE_
		SafeCall(Callable* f) noexcept : f(f)
		{
			OBFUSCATE_FUNCTION;
			__SET_LAST_STATE(ObfuscateStatus::PENDING_CALL);
		}

		template<typename... Args>
		__FORCE_INLINE_
		RetType operator()(Args&&... args) noexcept
		{
			OBFUSCATE_FUNCTION;

			if (!f) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_FUNCTION_ADDRESS);

				if constexpr (detail::is_same<RetType, void>)
					return;

				return RetType();
			}

			return ShellCodeManager<cc, RetType, Callable, Args...>(
									f, detail::forward<Args>(args)...);
		}
	};
	}
}

/* Undefine implementation macros to keep global namespace clean */

#ifdef __COMPILER_MSVC_
#undef __COMPILER_MSVC_
#endif
#ifdef __COMPILER_CLANG_
#undef __COMPILER_CLANG_
#endif
#ifdef __COMPILER_GCC_
#undef __COMPILER_GCC_
#endif
#ifdef __PLATFORM_WINDOWS_
#undef __PLATFORM_WINDOWS_
#endif
#ifdef __PLATFORM_LINUX_
#undef __PLATFORM_LINUX_
#endif
#ifdef __WINDOWS_KERNEL_
#undef __WINDOWS_KERNEL_
#endif
#ifdef __ARCH_X64_
#undef __ARCH_X64_
#endif
#ifdef __ARCH_X86_
#undef __ARCH_X86_
#endif
#ifdef __ARCH_ARM64_
#undef __ARCH_ARM64_
#endif
#ifdef __FORCE_INLINE_
#undef __FORCE_INLINE_
#endif
#ifdef __NO_INLINE_
#undef __NO_INLINE_
#endif
#ifdef __NO_STACK_PROTECT_
#undef __NO_STACK_PROTECT_
#endif
#ifdef __NO_CFG_
#undef __NO_CFG_
#endif
#ifdef __ALIGN_
#undef __ALIGN_
#endif
#ifdef __RESTRICT_
#undef __RESTRICT_
#endif
#ifdef __DEPRECATED_
#undef __DEPRECATED_
#endif
#ifdef __NO_SCS_
#undef __NO_SCS_
#endif
#ifdef __UNLIKELY_
#undef __UNLIKELY_
#endif
#ifdef __LIKELY_
#undef __LIKELY_
#endif
#ifdef __MAYBE_UNUSED_
#undef __MAYBE_UNUSED_
#endif
#ifdef __DISCARD_BRANCH_
#undef __DISCARD_BRANCH_
#endif
#ifdef __MEMORY_BARRIER_
#undef __MEMORY_BARRIER_
#endif
#ifdef __CDECL__
#undef __CDECL__
#endif
#ifdef __STDCALL__
#undef __STDCALL__
#endif
#ifdef __VECTORCALL__
#undef __VECTORCALL__
#endif
#ifdef __FASTCALL__
#undef __FASTCALL__
#endif
#ifdef __THISCALL__
#undef __THISCALL__
#endif
#ifdef __MS_ABI__
#undef __MS_ABI__
#endif
#ifdef __SYSV_ABI__
#undef __SYSV_ABI__
#endif
#ifdef __RETURN_ADDR_PTR_
#undef __RETURN_ADDR_PTR_
#endif
