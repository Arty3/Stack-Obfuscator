/* ************************************************************************** */

/*
	- License: MIT LICENSE
	- Author: https://github.com/Arty3

	- Requires:
		- C++20 or above,
		- MSVC / GCC / Clang
		- Windows 10 or above, alternatively Linux

	- Notes:
		- For GCC / Clang builds, please ensure
		  compilation with `-fno-omit-frame-pointer`

		- GCC does not support vector calls for
		  some ungodly reason, so use clang instead
*/

#pragma once

#if defined(_MSC_VER)
#define __COMPILER_MSVC_
#elif defined(__clang__) && defined(__GNUC__)
#define __COMPILER_CLANG_
#elif defined(__GNUC__) && defined(__GNUC_PATCHLEVEL__)
#define __COMPILER_GCC_
#else
#error "Unsupported compiler. This translation unit requires MSVC, Clang or GCC."
#endif

#if defined(_WIN32) || defined(_WIN64)
#define __PLATFORM_WINDOWS_
#if NTDDI_VERSION < NTDDI_WIN10_VB
#error "This translation unit requires Windows 10 or above."
#endif
#elif defined(__linux__)
#define __PLATFORM_LINUX_
#else
#error "Unsupported platform. This translation unit requires Windows or Linux."
#endif

#if defined(__PLATFORM_WINDOWS_) && defined(_KERNEL_MODE)
#define __WINDOWS_KERNEL_
#endif

#if defined(__PLATFORM_WINDOWS_)
#if defined(_M_X64) || defined(_M_AMD64)
#define __ARCH_X64_
#elif defined(_M_IX86)
#define __ARCH_X86_
#warning "32-bit architecture lacks support."
#elif defined(_M_ARM64)
#define __ARCH_ARM64_
#endif
#elif defined(__PLATFORM_LINUX_)
#if defined(__x86_64__) || defined(__amd64__)
#define __ARCH_X64_
#elif defined(__i386__)
#define __ARCH_X86_
#warning "32-bit architecture lacks support."
#elif defined(__aarch64__)
#define __ARCH_ARM64_
#endif
#else
#error "Unsupported architecture: This translation unit requires x86 or x86-64."
#endif

#if defined(__COMPILER_MSVC_)
#if !_HAS_CXX20 && defined(_MSVC_LANG) && _MSVC_LANG < 202002L
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
#include <emmintrin.h>
#include <random>
#elif defined(__PLATFORM_LINUX_)
#include <signal.h>
#include <unistd.h>
#include <cstdint>
#include <random>
#endif

#if defined(__COMPILER_MSVC_)
#define __FORCE_INLINE_		__forceinline
#define __NO_INLINE_		__declspec(noinline)
#define __NO_STACK_PROTECT_	__declspec(safebuffers)
#define __NO_CFG_			__declspec(guard(nocf))
#define __ALIGN_(x)			__declspec(align(x))
#define __RESTRICT_			__restrict
#elif defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_)
#define __FORCE_INLINE_		__attribute__((always_inline)) inline
#define __NO_INLINE_		__attribute__((noinline))
#define __NO_STACK_PROTECT_	__attribute__((no_stack_protector))
#if defined(__COMPILER_CLANG_) && __has_feature(cfi)
#define __NO_CFG_			__attribute__((no_sanitize("cfi")))
#elif (defined(__COMPILER_CLANG_) && __clang_major__ >= 7) \
	|| (defined(__COMPILER_GCC_) && __GNUC__ >= 9)
#define __NO_CFG_			__attribute__((nocf_check))
#else
#define __NO_CFG_
#endif
#define __ALIGN_(x)			__attribute__((aligned(x)))
#define __RESTRICT_			__restrict__
#endif

#if !defined(__WINDOWS_KERNEL_)
#define __UNLIKELY_	[[unlikely]]
#else
#define __UNLIKELY_
#endif

#if defined(__PLATFORM_WINDOWS_) && defined(__COMPILER_MSVC_)
#define __MEMORY_BARRIER_()	_mm_mfence()
#elif defined(__WINDOWS_KERNEL_)
#define __MEMORY_BARRIER_()	KeMemoryBarrier()
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
#define __CDECL__		__attribute__((cdecl))
#define __STDCALL__		__attribute__((stdcall))
#if defined(__COMPILER_CLANG_)
#define __VECTORCALL__	__attribute__((vectorcall))
#else
/* GCC doesnt support vector calls */
#define __VECTORCALL__
#endif
#define __FASTCALL__	__attribute__((fastcall))
#define __THISCALL__	__attribute__((thiscall))
#define __MS_ABI__		__attribute__((ms_abi))
#define __SYSV_ABI__	__attribute__((sysv_abi))
#endif

#if defined(__COMPILER_MSVC_)
#define __RETURN_ADDR_PTR_()	_AddressOfReturnAddress()
#elif defined(__COMPILER_CLANG_) || defined(__COMPILER_GCC_)
namespace __STACK_FRAGILE__
{
	static __FORCE_INLINE_
	int __probably_has_frame_ptr(volatile void** __RESTRICT_ frame_ptr)
	{
		const uintptr_t fp = (const uintptr_t)frame_ptr;
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

	static __FORCE_INLINE_
	void* __get_return_address_ptr(void)
	{
#pragma message("Remember to compile using `-fno-omit-frame-pointer` to ensure proper behavior.")
#if defined(_DEBUG) || defined(__DEBUG) || defined(__DEBUG__) || defined(DEBUG) && !defined(NDEBUG)
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

#if defined(_DEBUG) || defined(__DEBUG) || defined(__DEBUG__) || defined(DEBUG) && !defined(NDEBUG)
		if (!checked)
		{
			if (!__STACK_FRAGILE__::__probably_has_frame_ptr(frame_ptr))
				write(
					STDERR_FILENO,
					"WARNING: Frame pointer appears invalid (-fno-omit-frame-pointer)\n",
					65 * sizeof(char)
				);
			checked = 1;
		}
#endif

		/* Return address is at [rbp+8] on x64 */
		return reinterpret_cast<void*>(const_cast<void**>(frame_ptr + 1));
	}
}

#define __RETURN_ADDR_PTR_()	\
	__STACK_FRAGILE__::__get_return_address_ptr()

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
	UNINITIALIZED_TLS,
	INVALID_ENCRYPTION,
	INVALID_FUNCTION_ADDRESS,
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

#pragma intrinsic(__readgsqword)

/* https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/teb/index.htm */
#if defined(__ARCH_X64_)
#define __TLS_SLOTS_OFFSET		0x1480
#else
#define __TLS_SLOTS_OFFSET		0x0E10
#endif
/* Defined as `PVOID TlsSlots[0x40];` */
#define __TLS_SLOTS_SIZE		(0x40 * sizeof(PVOID))
/* Starting at slot 0x290 */
#define __TLS_SLOT_START_INDEX	(0x1480 / sizeof(PVOID))
/* Using slots 0x290-0x297 */
#define __TLS_SLOTS_USED		8

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

#if defined(__WINDOWS_KERNEL_)
#define REGISTER_OBFUSCATOR_THREAD_CLEANUP		__StackObfuscator::detail::__RegisterThreadCleanup()
#define UNREGISTER_OBFUSCATOR_THREAD_CLEANUP	__StackObfuscator::detail::__UnregisterThreadCleanup()
#define ALLOW_TLS_OVERWRITE						__StackObfuscator::detail::__ALLOW_TLS_OVERWRITE
#define LAST_THREAD_STATE						__StackObfuscator::detail::__LAST_THREAD_STATE
#define OBFUSCATOR_TLS_OFFSET					sizeof(__StackObfuscator::detail::ThreadState)
#endif

/* Avoid using the implementation directly */
namespace __StackObfuscator
{
	inline namespace detail
	{
#if !defined(__WINDOWS_KERNEL_)
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

	LastThreadStatus	__LAST_THREAD_STATE		= LastThreadStatus::UNINITIALIZED_GLOBAL;
	BOOLEAN				__ALLOW_TLS_OVERWRITE	= TRUE;
	KSPIN_LOCK			__LAST_THREAD_STATE_LOCK;

	/* Important kernel mode memory alignment */
	struct DECLSPEC_ALIGN(64) ThreadState
	{
		UINT64				s[4];			/* Key related data		*/
		UINT64				current_key;	/* Thread local key		*/
		BOOLEAN				initialized;	/* Thread init state	*/
		::ObfuscateStatus	last_state;		/* Last internal state	*/
	};

	static_assert(
		sizeof(ThreadState) <= __TLS_SLOTS_SIZE,
		"Structure must fit within TLS allocation"
	);

	__FORCE_INLINE_
	ThreadState* getThreadState(void) noexcept
	{
		if (!__ALLOW_TLS_OVERWRITE)
			return nullptr;

		PVOID teb = PsGetCurrentThreadTeb();

		if (!teb)
			return nullptr;

		const PVOID tls_location = (PVOID)(
			(ULONG_PTR)teb + __TLS_SLOTS_OFFSET
		);

		return (ThreadState*)tls_location;
	}

	__FORCE_INLINE_
	void __SET_LAST_STATE(ObfuscateStatus status) noexcept
	{
		ThreadState* __RESTRICT_ state = getThreadState();

		if (!state)
			return;

		state->last_state = status;
	}

	__FORCE_INLINE_
	ObfuscateStatus __GET_LAST_STATE(void) noexcept
	{
		ThreadState* __RESTRICT_ state = getThreadState();

		if (!state)
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
			
			if (!__verify_entropy_quality(state->current_key))
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
			if (initialized)
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
			if (!key)
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

			if (all_same)
				return false;

#if defined(__COMPILER_MSVC_)
			const int popcount = __popcnt64(key);
			return popcount >= 20 && popcount <= 44;
#else
#if __has_builtin(__builtin_popcountll)
			const int popcount = __builtin_popcountll(key);
			return popcount >= 20 && popcount <= 44;
#else
			/* For old CPUs without popcount: 
			 * check if upper and lower
			 * halves are different */
			uint32_t upper = (uint32_t)(key >> 32);
			uint32_t lower = (uint32_t)(key & 0xFFFFFFFF);
			
			if (upper == lower)
				return false;

			if (upper == lower + 1 || upper == lower - 1)
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
			if (state->initialized)
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
			ThreadState* __RESTRICT_ state = getThreadState();

			if (!state)
				return 0;

			return state->current_key;
		}
#else

		static __FORCE_INLINE_
		uintptr_t getKey(void) noexcept
		{
			if (current_key)
				return current_key;

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

			return current_key;
		}
#endif
	};

#if defined(__WINDOWS_KERNEL_)
	__FORCE_INLINE_
	void initThreadState(void) noexcept
	{
		if (!__ALLOW_TLS_OVERWRITE)
			return;

		ThreadState* __RESTRICT_ state = getThreadState();

		KIRQL oldIrql;

		KeAcquireSpinLock(&__LAST_THREAD_STATE_LOCK, &oldIrql);

		if (!state)
		{
			__LAST_THREAD_STATE = LastThreadStatus::INIT_FAILURE;
			KeReleaseSpinLock(&__LAST_THREAD_STATE_LOCK, oldIrql);
			return;
		}

		RtlZeroMemory(state, sizeof(ThreadState));

		KeyGenerator::initThreadStateKey(state);

		state->initialized	= TRUE;
		state->last_state	= ObfuscateStatus::INITIALIZED;
		__LAST_THREAD_STATE	= LastThreadStatus::INIT_SUCCESS;

		KeReleaseSpinLock(&__LAST_THREAD_STATE_LOCK, oldIrql);
	}

	VOID __ThreadNotifyCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) noexcept
	{
		UNREFERENCED_PARAMETER(ProcessId);
		UNREFERENCED_PARAMETER(ThreadId);

		KIRQL oldIrql;

		if (Create)
		{
			KeAcquireSpinLock(&__LAST_THREAD_STATE_LOCK, &oldIrql);
			__LAST_THREAD_STATE = LastThreadStatus::THREAD_IS_CREATING;
			initThreadState();
			KeReleaseSpinLock(&__LAST_THREAD_STATE_LOCK, oldIrql);
		}
		else
		{
			KeAcquireSpinLock(&__LAST_THREAD_STATE_LOCK, &oldIrql);
			__LAST_THREAD_STATE = LastThreadStatus::THREAD_TERMINATED;
			KeReleaseSpinLock(&__LAST_THREAD_STATE_LOCK, oldIrql);
		}
	}

	__FORCE_INLINE_
	NTSTATUS __RegisterThreadCleanup(void) noexcept
	{
		KeInitializeSpinLock(&__LAST_THREAD_STATE_LOCK);
		return PsSetCreateThreadNotifyRoutine(__ThreadNotifyCallback);
	}

	__FORCE_INLINE_
	NTSTATUS __UnregisterThreadCleanup(void) noexcept
	{
		return PsRemoveCreateThreadNotifyRoutine(__ThreadNotifyCallback);
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

	class ObfuscateFunction
	{
	private:
		const uintptr_t	xor_key;
		void*			ret_addr	= nullptr;
		bool			initialized	= false;
		uintptr_t		tmp			= 0;

	public:
		__NO_CFG_ __FORCE_INLINE_
		ObfuscateFunction(void* addr) noexcept
			: xor_key(KeyGenerator::getKey()), ret_addr(addr)
		{
			if (!addr) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_FUNCTION_ADDRESS);
				return;
			}

			if (!xor_key) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);
				return;
			}

			tmp = (*(uintptr_t*)ret_addr) ^ xor_key;
			__MEMORY_BARRIER_();
			*(uintptr_t*)ret_addr = 0;

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

			if (!xor_key) __UNLIKELY_
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);
				return;
			}

			*(uintptr_t*)ret_addr = tmp ^ xor_key;

			__MEMORY_BARRIER_();
			__verify_return_addr(ret_addr);
			__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
		}
	};

	template <CallingConvention cc, typename RetType, typename Callable, typename... Args>
	__NO_CFG_ __NO_STACK_PROTECT_
	RetType ShellCodeManager(Callable* f, Args&&... args) noexcept
	{
		OBFUSCATE_FUNCTION;

		const uintptr_t	xor_key = KeyGenerator::getKey();

		if (!xor_key) __UNLIKELY_
		{
			__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);
			if constexpr (detail::is_same<RetType, void>)
				return;
			return RetType();
		}

		void* __RESTRICT_ ret_addr = __RETURN_ADDR_PTR_();
		__MEMORY_BARRIER_();
		uintptr_t tmp = *(uintptr_t*)ret_addr ^ xor_key;
		__MEMORY_BARRIER_();
		*(uintptr_t*)ret_addr = 0;

		/* Unfortunately C++ only supports constexpr for if statements
		 * So readability & portability is thrown out the window
		 * In this case its appropriate to do so for efficiency */

		if constexpr (cc == CallingConvention::__CDECL)
		{
			auto function = reinterpret_cast<RetType(__CDECL__*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}
#if defined(__PLATFORM_WINDOWS_)
		else if constexpr (cc == CallingConvention::__STDCALL)
		{
			auto function = reinterpret_cast<RetType(__STDCALL__*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}
#endif
#if defined(__PLATFORM_WINDOWS_) && defined(_MANAGED)
		else if constexpr (cc == CallingConvention::__CLRCALL)
		{
			auto function = reinterpret_cast<RetType(__clrcall*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);

				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);

				return ret;
			}
		}

#elif defined(__PLATFORM_WINDOWS_) && !defined(__COMPILER_GCC_) && !defined(_MANAGED)
		else if constexpr (cc == CallingConvention::__VECTORCALL)
		{
			auto function = reinterpret_cast<RetType(__VECTORCALL__*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);

				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);

				return ret;
			}
		}
#endif
#if defined(__PLATFORM_WINDOWS_) && !defined(__ARCH_X64_) && !defined(__ARCH_ARM64_)
		else if constexpr (cc == CallingConvention::__FASTCALL)
		{
			auto function = reinterpret_cast<RetType(__FASTCALL__*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}
#endif
#if defined(__PLATFORM_WINDOWS_)
		else if constexpr (cc == CallingConvention::__THISCALL)
		{
			auto function = reinterpret_cast<RetType(__THISCALL__*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}
#endif
#if defined(__PLATFORM_LINUX_) && !defined(__COMPILER_MSVC_)
		else if constexpr (cc == CallingConvention::__MS_ABI)
		{
			auto function = reinterpret_cast<RetType(__MS_ABI__*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}
#endif
#if defined(__COMPILER_GCC_) || defined(__COMPILER_CLANG_)
		else if constexpr (cc == CallingConvention::__SYSV_ABI)
		{
			auto function = reinterpret_cast<RetType(__SYSV_ABI__*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				__MEMORY_BARRIER_();
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
				__MEMORY_BARRIER_();
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}
#endif

		__SET_LAST_STATE(ObfuscateStatus::INVALID_CALLING_CONVENTION);

		__MEMORY_BARRIER_();
		*(uintptr_t*)ret_addr = tmp ^ xor_key;
		__MEMORY_BARRIER_();

		__verify_return_addr(ret_addr);
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

			return ShellCodeManager<cc, RetType, Callable, Args...>(f, detail::forward<Args>(args)...);
		}
	};
	}
}
