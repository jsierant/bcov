#ifndef H_Debugger
#define H_Debugger
//---------------------------------------------------------------------------
#include <map>
#include <vector>
#include <string>
//---------------------------------------------------------------------------
/// Interface for the debugger
class Debugger
{
   public:
   /// Breakpoint information
   class BreakpointInfo {
      private:
      /// The original code
      unsigned char oldCode;

      friend class Debugger;

      public:
      /// Hit count
      unsigned hits;
   };
   /// Possible events
   enum Event { Error, Exit, Trap };

   private:
   /// The child
   long child;
   /// The currently active child (can be different when threaded)
   long activeChild;
   /// A map of base adresses for loaded modules
   std::map<std::string,unsigned long> baseAddress;
   /// active status
   bool active;
   bool checkActive;

   public:
   /// Constructor
   Debugger();
   /// Destructor
   ~Debugger();

   /// Load a program
   bool load(const std::string& executable,const std::vector<std::string>& arguments);
   /// Close the debugger
   bool close();

   bool loadBaseAddresses();
   unsigned long getBaseAddress(std::string library);

   /// Set breakpoints
   bool setBreakpoints(std::map<void*,BreakpointInfo>& addresses);
   /// Remove breakpoints
   bool removeBreakpoints(std::map<void*,BreakpointInfo>& addresses);
   /// Remove the breakpoint we just hit and adjust IP
   void eliminateHitBreakpoint(BreakpointInfo& i);
   /// Skip the breakpoint we just hit and adjust IP
   void skipHitBreakPoint(BreakpointInfo& i);
   /// Run the program
   Event run();
   /// Get the current IP
   void* getIP();
   /// Get the current IP if we executed a trap instruction
   void* getIPBeforeTrap();
   
   /// active status
   void setActive(bool active);
   bool getActive();
};
//---------------------------------------------------------------------------
#endif
