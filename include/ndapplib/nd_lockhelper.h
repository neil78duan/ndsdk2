/* file nd_lockhelper.h
 *
 * define class of lock helper
 *
 * 2010/12/24 14:53:26
 */

#ifndef _ND_LOCKHELP_H_
#define _ND_LOCKHELP_H_


//#include "nd_common/nd_common.h"
#include "ndapplib/nd_object.h"
class  ND_COMMON_CLASS LockHelper
{
public:
	LockHelper(nd_mutex *lock)
	{
		//NDCallTrace name("nd_mutex_lock") ;
		m_lock = lock ;
		nd_mutex_lock(lock) ;
	}
	
	LockHelper() :m_lock(0) {}

	inline bool tryLock(nd_mutex *lock)
	{
		//NDCallTrace name("nd_mutex_trylock");
		if (0 == nd_mutex_trylock(lock)) {
			m_lock = lock;
			return true;
		}
		return false;
	}
	inline bool isLocked() { return m_lock ? true : false; }
	~LockHelper() 
	{
		if(m_lock)nd_mutex_unlock(m_lock) ;
	}
private:
	nd_mutex *m_lock ; 
};

#endif 
