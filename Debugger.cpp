/*
   Copyright (C) 2007 Thomas Neumann

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation version 2.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.  */
//---------------------------------------------------------------------------
#include "Debugger.hpp"
#include <iostream>
#include <fstream>
#include <cerrno>
#include <string>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
//---------------------------------------------------------------------------
using namespace std;
//---------------------------------------------------------------------------
static unsigned char peekbyte(pid_t child,const void* ptr)
   // Read client memory
{
   unsigned long addr=reinterpret_cast<unsigned long>(ptr);
   unsigned long aligned=(addr/sizeof(long))*sizeof(long);
   union { long val; unsigned char data[sizeof(long)]; } data;
   data.val=ptrace(PTRACE_PEEKTEXT,child,aligned,0);
   //if (data.val==-1) {
   //  cerr << "ptrace(PTRACE_PEEKTEXT," << child << "," << aligned << ") failed: " << strerror(errno) << endl;
   //}
   return data.data[addr-aligned];
}
//---------------------------------------------------------------------------
static void pokebyte(pid_t child,void* ptr,unsigned char c)
   // Write client memory
{
   unsigned long addr=reinterpret_cast<unsigned long>(ptr);
   unsigned long aligned=(addr/sizeof(long))*sizeof(long);
   union { long val; unsigned char data[sizeof(long)]; } data;
   data.val=ptrace(PTRACE_PEEKTEXT,child,aligned,0);
   data.data[addr-aligned]=c;
   ptrace(PTRACE_POKETEXT,child,aligned,data.val);
}
//---------------------------------------------------------------------------
Debugger::Debugger()
   : child(0), active(true), checkActive(false) 
   // Constructor
{
}
//---------------------------------------------------------------------------
Debugger::~Debugger()
   // Destructor
{
}
//---------------------------------------------------------------------------
bool Debugger::load(const string& executable,const vector<string>& arguments)
   // Load a program
{
   // Close first if needed
   close();

   // Basic check first
   if (access(executable.c_str(),X_OK)!=0)
      return false;

   // Executable exists, try to launch it
   if ((child=fork())==0) {
      // Construct the arguments array
      vector<const char*> args;
      args.push_back(executable.c_str());
      for (vector<string>::const_iterator iter=arguments.begin(),limit=arguments.end();iter!=limit;++iter)
         args.push_back((*iter).c_str());
      args.push_back(0);
      // And launch the process
      ptrace(PTRACE_TRACEME,0,0,0);
      execv(executable.c_str(),const_cast<char**>(&args[0]));
      // Exec failed
      _exit(127);
   }

   // Fork error?
   if (child==-1) {
      child=0;
      return false;
   }

   // Wait for the initial stop
   int status;
   if ((waitpid(child,&status,0)==-1)||(!WIFSTOPPED(status))) {
      close();
      return false;
   }
   ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_TRACECLONE);
   activeChild=child;

   return true;
}
//---------------------------------------------------------------------------
bool Debugger::close()
   // Close the debugger
{
   if (child) {
      ptrace(PTRACE_KILL,child,0,0);
      child=0;
   }
   return true;
}
//---------------------------------------------------------------------------
bool Debugger::loadBaseAddresses()
{
   // grep it from /proc/self/maps, first column is address
   char fname[25];

   snprintf(fname,sizeof(fname),"/proc/%ld/maps",child);

   ifstream in(fname);
   if (!in.is_open()) {
      cerr << "unable to read " << fname << endl;
      return false;
   }
   // 00a07000-00b45000 r-xp 00000000 08:01 131846     /lib/tls/i686/cmov/libc-2.10.1.so
   string line;
   while (getline(in,line)) {
      // filter " r-xp "
      if (strstr(line.c_str(), " r-xp ")) {
         const char *pos=strrchr(line.c_str(),' ');
         if(pos && pos[1]!='[') {
            // first 8 bytes is address in hex without 0x
            unsigned long addr=0,v;
            for(int i=0;i<8;i++) {
               if((line[i]>='0') && (line[i]<='9'))
                  v=line[i]-'0';
               else
                  v=10+(line[i]-'a');
               addr=(addr<<4)|v;
               //cout << "  [" << i << "] : " << v << " : " << addr << endl;
            }

            string name=&pos[1];
            baseAddress[name]=addr;

            //cout << "base addr " << name << " : " << addr << endl;
         }
      }
   }
   in.close();
   return true;
}
//---------------------------------------------------------------------------
unsigned long Debugger::getBaseAddress(std::string library)
{
  return baseAddress[library];
}
//---------------------------------------------------------------------------
bool Debugger::setBreakpoints(map<void*,BreakpointInfo>& addresses)
   // Set breakpoints
{
   if (!child)
      return false;

   // Set the breakpoints
   for (map<void*,BreakpointInfo>::iterator iter=addresses.begin(),limit=addresses.end();iter!=limit;++iter) {
      (*iter).second.oldCode=peekbyte(child,(*iter).first);
      (*iter).second.hits=0;
#if defined(__x86_64__)||defined(__i386__)
      pokebyte(child,(*iter).first,0xCC);
#else
   #error specify how to set a breakpoint
#endif
   }
   return true;
}
//---------------------------------------------------------------------------
bool Debugger::removeBreakpoints(map<void*,BreakpointInfo>& addresses)
   // Remove breakpoints
{
   if (!child)
      return false;

   // Set the breakpoints
   for (map<void*,BreakpointInfo>::iterator iter=addresses.begin(),limit=addresses.end();iter!=limit;++iter) {
      pokebyte(child,(*iter).first,(*iter).second.oldCode);
   }
   return true;
}
//---------------------------------------------------------------------------
void Debugger::eliminateHitBreakpoint(BreakpointInfo& i)
   // Remove the breakpoint we just hit and adjust IP
{
   user_regs_struct regs;
   memset(&regs,0,sizeof(regs));
   ptrace(PTRACE_GETREGS,activeChild,0,&regs);
#if defined(__x86_64__)
   void* ptr=reinterpret_cast<void*>(--regs.rip);
#elif defined(__i386__)
   void* ptr=reinterpret_cast<void*>(--regs.eip);
#else
   #error specify how to adjust the IP after a breakpoint
#endif
   ptrace(PTRACE_SETREGS,activeChild,0,&regs);
   pokebyte(activeChild,ptr,i.oldCode);
}
//---------------------------------------------------------------------------
void Debugger::skipHitBreakPoint(BreakpointInfo& i)
   // Skip the breakpoint we just hit and adjust IP
{
   user_regs_struct regs;
   memset(&regs,0,sizeof(regs));
   ptrace(PTRACE_GETREGS,activeChild,0,&regs);
#if defined(__x86_64__)
   void* ptr=reinterpret_cast<void*>(--regs.rip);
#elif defined(__i386__)
   void* ptr=reinterpret_cast<void*>(--regs.eip);
#else
   #error specify how to adjust the IP after a breakpoint
#endif
   ptrace(PTRACE_SETREGS,activeChild,0,&regs);
   pokebyte(activeChild,ptr,i.oldCode);
   // step one instruction:
   ptrace(PTRACE_SINGLESTEP,activeChild,0,0);
   // put breakpoint back
#if defined(__x86_64__)||defined(__i386__)
   pokebyte(activeChild,ptr,0xCC);
#else
   #error specify how to set a breakpoint
#endif
   // FIXME: should we check the status like in ::run()?
   int status;
   waitpid(-1,&status,__WALL);
}
//---------------------------------------------------------------------------
Debugger::Event Debugger::run()
   // Run the program
{
   // Continue the stopped child
   ptrace(PTRACE_CONT,activeChild,0,0);

   while (true) {
      // Wait for a child
      int status;
      pid_t r=waitpid(-1,&status,__WALL);

      // Got no one?
      if (r==-1)
         return Error;
      activeChild=r;

      // A signal?
      if (WIFSTOPPED(status)) {
         // enable/disable logging
         if (WSTOPSIG(status)==SIGUSR1) {
           if (checkActive) {
             cout << "** Bcov logging on" << endl;
             active=true;
           }
           ptrace(PTRACE_CONT,activeChild,0,0);
           continue;
         }          
         if (WSTOPSIG(status)==SIGUSR2) {
           if (checkActive) {
             active=false;
             cout << "** Bcov logging off" << endl;
           }
           ptrace(PTRACE_CONT,activeChild,0,0);
           continue;
         }          
         // A trap?
         if (WSTOPSIG(status)==SIGTRAP)
            return Trap;
         // No, deliber it directly
         ptrace(PTRACE_CONT,activeChild,0,WSTOPSIG(status));
         continue;
      }
      // Thread died?
      if (WIFSIGNALED(status)||WIFEXITED(status)) {
         if (activeChild==child)
            return Exit;
         continue;
      }
      // Stopped?
      if (WIFSTOPPED(status)) {
         // A new clone? Ignore the stop event
         if ((status>>8)==PTRACE_EVENT_CLONE) {
            ptrace(PTRACE_CONT,activeChild,0,0);
            continue;
         }
         // Hm, why did we stop? Ignore the event and continue
         ptrace(PTRACE_CONT,activeChild,0,0);
         continue;
      }
      // Unknown event
      return Error;
   }
}
//---------------------------------------------------------------------------
void* Debugger::getIP()
   // Get the current IP
{
   user_regs_struct regs;
   memset(&regs,0,sizeof(regs));
   ptrace(PTRACE_GETREGS,activeChild,0,&regs);
#if defined(__x86_64__)
   return reinterpret_cast<void*>(regs.rip);
#elif defined(__i386__)
   return reinterpret_cast<void*>(regs.eip);
#else
   #error specify how to read the IP
#endif
}
//---------------------------------------------------------------------------
void* Debugger::getIPBeforeTrap()
   // Get the current IP if we executed a trap instruction
{
#if defined(__x86_64__)||defined(__i386__)
   return static_cast<char*>(getIP())-1;
#else
   #error specify how to adjust the IP after a breakpoint
#endif
}
//---------------------------------------------------------------------------
void Debugger::setActive(bool active)
{
  this->active=active;
  if (!active) {
    // check for activation via SIGUSR1
    checkActive=true;
  }
}

bool Debugger::getActive()
{
  return active;
}
