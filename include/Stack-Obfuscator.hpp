/* ************************************************************************** */

/*
	- License: GNU GENERAL PUBLIC LICENSE v3.0
	- Author: https://github.com/DontCallMeLuca
	- Requires: C++20 or above, Windows 10 or above
*/

#pragma once

#ifndef _MSC_VER
#error "This translation unit requires the MSVC compiler"
#endif

#if !_HAS_CXX20 && defined(_MSVC_LANG) && _MSVC_LANG < 202002L
#error "This translation unit requires C++20 or above."
#endif

#if (NTDDI_VERSION < NTDDI_WIN10_VB)
#error "This translation unit requires Windows 10 or above."
#endif

#ifdef _M_IX86
#pragma message("WARNING: 32-bit architecture lacks support.")
#endif

#ifdef _KERNEL_MODE
#include <ntifs.h>
#else
#include <Windows.h>
#include <random>
#endif

#include <Intrin.h>

enum class CallingConvention : unsigned __int8
{
	__CDECL,
	__STDCALL,
#ifdef _MANAGED
	__CLRCALL,
#else
	__VECTORCALL,
#endif
#ifndef _M_X64
	__FASTCALL,
#endif
	__THISCALL,
};

enum class ObfuscateStatus : unsigned __int8
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

#ifdef _KERNEL_MODE
enum class LastThreadStatus : unsigned __int8
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
#ifdef _M_X64
# define __TLS_SLOTS_OFFSET	0x1480
#else
# define __TLS_SLOTS_OFFSET	0x0E10
#endif

/* Defined as `PVOID TlsSlots[0x40];` */
#define __TLS_SLOTS_SIZE	(0x40 * sizeof(PVOID))

#endif

/* See the API section in README.md */

#define OBFUSCATE_FUNCTION	__StackObfuscator::detail::ObfuscateFunction \
								obfuscate(_AddressOfReturnAddress())

/* Better practice to use the other macros instead. */
#define OBFUSCATE_CALL(ret_type, convention, name)		\
		(__StackObfuscator::detail::SafeCall<ret_type,	\
		convention, __StackObfuscator::detail::			\
		remove_reference_t<decltype(*name)>>(			\
		__StackObfuscator::detail::forward<				\
		decltype(name)>(name)))

#define OBFUSCATOR_LAST_STATE			__StackObfuscator::detail::__GET_LAST_STATE()

#define	OBFUSCATE_CDECL(ret, name)		OBFUSCATE_CALL(ret, CallingConvention::__CDECL,			name)
#define	OBFUSCATE_STDCALL(ret, name)	OBFUSCATE_CALL(ret, CallingConvention::__STDCALL,		name)
#ifndef _M_X64
#define	OBFUSCATE_FASTCALL(ret, name)	OBFUSCATE_CALL(ret, CallingConvention::__FASTCALL,		name)
#endif
#define	OBFUSCATE_THISCALL(ret, name)	OBFUSCATE_CALL(ret, CallingConvention::__THISCALL,		name)
#ifndef	_MANAGED
#define	OBFUSCATE_VECTORCALL(ret, name)	OBFUSCATE_CALL(ret, CallingConvention::__VECTORCALL,	name)
#else
#define	OBFUSCATE_CLRCALL(ret, name)	OBFUSCATE_CALL(ret, CallingConvention::__CLRCALL,		name)
#endif

#ifdef _KERNEL_MODE
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
#ifndef _KERNEL_MODE
	ObfuscateStatus thread_local __LAST_STATE = ObfuscateStatus::INITIALIZED;

	__forceinline void __SET_LAST_STATE(ObfuscateStatus status) noexcept
	{
		__LAST_STATE = status;
	}

	__forceinline ObfuscateStatus __GET_LAST_STATE(void) noexcept
	{
		return __LAST_STATE;
	}
#else
	typedef unsigned __int64 uintptr_t;

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

	__forceinline ThreadState* getThreadState(void) noexcept
	{
		if (!__ALLOW_TLS_OVERWRITE)
			return nullptr;

		static const PVOID _TLS_LOCATION = (PVOID)(
			(ULONG_PTR)PsGetCurrentThreadTeb() + __TLS_SLOTS_OFFSET
		);

		return (ThreadState*)_TLS_LOCATION;
	}

	__forceinline void __SET_LAST_STATE(ObfuscateStatus status) noexcept
	{
		ThreadState* __restrict state = getThreadState();

		if (!state)
			return;

		state->last_state = status;

		KeMemoryBarrier();
	}

	__forceinline ObfuscateStatus __GET_LAST_STATE(void) noexcept
	{
		ThreadState* __restrict state = getThreadState();

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

	/* Encryption is done manually in kernel mode due to lack of STL */
	class KeyGenerator
	{
	private:
#ifdef _KERNEL_MODE
		static __forceinline UINT64 rotl(const UINT64 x, int k) noexcept
		{
			return (x << k) | (x >> (64 - k));
		}

		static __forceinline void addEntropy(ThreadState* state) noexcept
		{
			if (!state)
				return;

			state->s[0] ^= __rdtsc();
			state->s[1] ^= KeQueryPerformanceCounter(nullptr).QuadPart;

			KeMemoryBarrier();
		}

		static __forceinline UINT64 next(ThreadState* __restrict state) noexcept
		{
			const UINT64 result	= rotl(state->s[1] * 5, 7) * 9;
			const UINT64 t		= state->s[1] << 17;

			state->s[2] ^= state->s[0];
			state->s[3] ^= state->s[1];
			state->s[1] ^= state->s[2];
			state->s[0] ^= state->s[3];

			state->s[2] ^= t;
			state->s[3] = rotl(state->s[3], 45);

			KeMemoryBarrier();

			addEntropy(state);

			return result;
		}
#else
		using distribution = std::uniform_int_distribution<uintptr_t>;

		static inline thread_local uintptr_t		current_key;
		static inline thread_local bool				initialized;
		static inline thread_local std::mt19937_64	thread_gen;
		static inline thread_local distribution		thread_dis;

		static __forceinline void initThreadLocal(void) noexcept
		{
			if (initialized)
				return;

			std::random_device rd;
			thread_gen.seed(rd());
			initialized = true;
		}
#endif
	public:
#ifdef _KERNEL_MODE
		static __forceinline void initThreadStateKey(ThreadState* __restrict state) noexcept
		{
			if (state->initialized)
				return;

			LARGE_INTEGER time;
			KeQuerySystemTime(&time);

			state->s[0] = time.QuadPart;
			state->s[1] = __rdtsc();
			state->s[2] = (UINT64)PsGetCurrentProcess();
			state->s[3] = (UINT64)PsGetCurrentThread();

			constexpr const int KEY_GEN_ROUNDS = 16;
			for (int i = 0; i < KEY_GEN_ROUNDS; ++i)
				next(state);

			state->current_key = 0;
			KeMemoryBarrier();
		}

		static __forceinline UINT64 getKey(void) noexcept
		{
			ThreadState* __restrict state = getThreadState();

			if (!state)
				return 0;

			return state->current_key;
		}
	#else
		static __forceinline uintptr_t getKey(void) noexcept
		{
			if (current_key)
				return current_key;

			initThreadLocal();

			while (!current_key)
				current_key = thread_dis(thread_gen);

			return current_key;
		}
	};

#ifdef _KERNEL_MODE
	__forceinline void initThreadState(void) noexcept
	{
		if (!__ALLOW_TLS_OVERWRITE)
			return;

		ThreadState* __restrict state = getThreadState();

		KIRQL oldIrql;

		KeAcquireSpinLock(&__LAST_THREAD_STATE_LOCK, &oldIrql);

		if (!state)
		{
			__LAST_THREAD_STATE = LastThreadStatus::INIT_FAILURE;

			KeMemoryBarrier();

			KeReleaseSpinLock(&__LAST_THREAD_STATE_LOCK, oldIrql);

			return;
		}

		RtlZeroMemory(state, sizeof(ThreadState));

		KeyGenerator::initThreadStateKey(state);

		state->initialized	= TRUE;
		state->last_state	= ObfuscateStatus::INITIALIZED;
		__LAST_THREAD_STATE	= LastThreadStatus::INIT_SUCCESS;

		KeMemoryBarrier();

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
			KeMemoryBarrier();

			KeReleaseSpinLock(&__LAST_THREAD_STATE_LOCK, oldIrql);

			initThreadState();
		}
		else
		{
			KeAcquireSpinLock(&__LAST_THREAD_STATE_LOCK, &oldIrql);
			__LAST_THREAD_STATE = LastThreadStatus::THREAD_TERMINATED;
			KeMemoryBarrier();

			KeReleaseSpinLock(&__LAST_THREAD_STATE_LOCK, oldIrql);
		}
	}

	__forceinline NTSTATUS __RegisterThreadCleanup(void) noexcept
	{
		return PsSetCreateThreadNotifyRoutine(__ThreadNotifyCallback);
	}

	__forceinline NTSTATUS __UnregisterThreadCleanup(void) noexcept
	{
		return PsRemoveCreateThreadNotifyRoutine(__ThreadNotifyCallback);
	}
#endif

	/* Doesn't protect against value manipulation */
	/* See https://github.com/DontCallMeLuca/Stack-Protector */
	static __forceinline void __verify_return_addr(void* addr)
	{
		/* We know the addr should never be 0x0 */
		if (!addr)
		{
			__SET_LAST_STATE(ObfuscateStatus::CORRUPT_KEY_OR_STACK_ADDR);
#ifdef _KERNEL_MODE
			/* BSOD (Bluescreen) */
			KeBugCheckEx(
				CRITICAL_STRUCTURE_CORRUPTION,
				(ULONG_PTR)_ReturnAddress(),
				(ULONG_PTR)0xC0000000,
				(ULONG_PTR)addr, 0
			);
#else
			__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE);
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
		__declspec(guard(nocf))
		__forceinline ObfuscateFunction(void* addr) noexcept
			: ret_addr(addr), xor_key(KeyGenerator::getKey())
		{
			if (!addr)
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_FUNCTION_ADDRESS);
				return;
			}

			if (!xor_key)
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);
				return;
			}

			tmp = (*(uintptr_t*)ret_addr) ^ xor_key;
			*(uintptr_t*)ret_addr = 0;

			initialized = true;

#ifdef _KERNEL_MODE
			KeMemoryBarrier();
#endif
			__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
		}

		__declspec(guard(nocf)) __forceinline ~ObfuscateFunction(void) noexcept
		{
			if (!initialized)
			{
				ObfuscateStatus status = __GET_LAST_STATE();

				if (status != ObfuscateStatus::INVALID_FUNCTION_ADDRESS &&
					status != ObfuscateStatus::INVALID_ENCRYPTION)
					__SET_LAST_STATE(ObfuscateStatus::UNINITIALIZED_STACK_CLEANUP);

				return;
			}

			if (!xor_key)
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);
				return;
			}

			*(uintptr_t*)ret_addr = tmp ^ xor_key;

#ifdef _KERNEL_MODE
			KeMemoryBarrier();
#endif
			__verify_return_addr(ret_addr);
			__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
		}
	};

	template <CallingConvention cc, typename RetType, typename Callable, typename... Args>
	__declspec(guard(nocf)) __declspec(safebuffers)
	RetType ShellCodeManager(Callable* f, Args&&... args) noexcept
	{
		OBFUSCATE_FUNCTION;

		const uintptr_t	xor_key = KeyGenerator::getKey();

		if (!xor_key)
		{
			__SET_LAST_STATE(ObfuscateStatus::INVALID_ENCRYPTION);
			return RetType();
		}

		void* __restrict ret_addr = _AddressOfReturnAddress();
		uintptr_t tmp = *(uintptr_t*)ret_addr ^ xor_key;

		*(uintptr_t*)ret_addr = 0;

#ifdef _KERNEL_MODE
		KeMemoryBarrier();
#endif

		/* Unfortunately C++ only supports constexpr for if statements */
		/* So readability & portability is thrown out the window */
		/* In this case its appropriate to do so for efficiency */

		if constexpr (cc == CallingConvention::__CDECL)
		{
			auto function = reinterpret_cast<RetType(__cdecl*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}

		else if constexpr (cc == CallingConvention::__STDCALL)
		{
			auto function = reinterpret_cast<RetType(__stdcall*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}

#ifdef _MANAGED
		else if constexpr (cc == CallingConvention::__CLRCALL)
		{
			auto function = reinterpret_cast<RetType(__clrcall*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);

				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);

				return ret;
			}
		}
#else
		else if constexpr (cc == CallingConvention::__VECTORCALL)
		{
			auto function = reinterpret_cast<RetType(__vectorcall*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);

				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);

				return ret;
			}
		}
#endif
#ifndef _M_X64
		else if constexpr (cc == CallingConvention::__FASTCALL)
		{
			auto function = reinterpret_cast<RetType(__fastcall*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}
#endif
		else if constexpr (cc == CallingConvention::__THISCALL)
		{
			auto function = reinterpret_cast<RetType(__thiscall*)(remove_reference_t<Args>...)>(f);
			if constexpr (detail::is_same<RetType, void>)
			{
				function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return;
			}
			else
			{
				RetType ret = function(detail::forward<Args>(args)...);
				*(uintptr_t*)ret_addr = tmp ^ xor_key;
#ifdef _KERNEL_MODE
				KeMemoryBarrier();
#endif
				__verify_return_addr(ret_addr);
				__SET_LAST_STATE(ObfuscateStatus::SUCCEEDED);
				return ret;
			}
		}

		__SET_LAST_STATE(ObfuscateStatus::INVALID_CALLING_CONVENTION);

		*(uintptr_t*)ret_addr = tmp ^ xor_key;

#ifdef _KERNEL_MODE
		KeMemoryBarrier();
#endif
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
		__forceinline SafeCall(Callable* f) noexcept : f(f)
		{
			OBFUSCATE_FUNCTION;

			__SET_LAST_STATE(ObfuscateStatus::PENDING_CALL);
		}

		template<typename... Args>
		__forceinline RetType operator()(Args&&... args) noexcept
		{
			OBFUSCATE_FUNCTION;

			if (!f)
			{
				__SET_LAST_STATE(ObfuscateStatus::INVALID_FUNCTION_ADDRESS);
				return RetType();
			}

			return ShellCodeManager<cc, RetType, Callable, Args...>(f, detail::forward<Args>(args)...);
		}
	};
	}
}
