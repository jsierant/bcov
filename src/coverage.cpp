#include "Debugger.hpp"
#include <iostream>
#include <fstream>
#include <set>
#include <sys/fcntl.h>
#include <libelf/libelf.h>
#include <libdwarf/libdwarf.h>
//---------------------------------------------------------------------------
using namespace std;
//---------------------------------------------------------------------------
static void dwarfErrorHandler(Dwarf_Error error, Dwarf_Ptr /*userData*/)
   // Show the dwarf error message
{
   char* msg=dwarf_errmsg(error);
   cerr << "dwarf error: " << msg << endl;
}
//---------------------------------------------------------------------------
static string normalize(const string& filePath)
   // Normalize a file name
{
   // A quick scan first...
   bool hadSep=false,needsFix=false;
   string::size_type len=filePath.length();
   if (!needsFix)
   for (string::size_type index=0;index<len;index++) {
      char c=filePath[index];
      if (c=='/') {
         if (hadSep)
            needsFix=true;
         hadSep=true;
      } else {
         if (c=='.')
            if (hadSep||(index==0))
               needsFix=true;
         hadSep=false;
      }
   }
   if (!needsFix)
      return filePath;
   hadSep=false;
   // Construct the fixed result
   string result;
   for (string::size_type index=0;index<len;index++) {
      char c=filePath[index];
      if (c=='/') {
         if (hadSep) {
         } else result+=c;
         hadSep=true;
      } else {
         if ((c=='.')&&(hadSep||(index==0))) {
            if (index+1>=len) {
               if (hadSep)
                  result.resize(result.length()-1); else
                  result+=c;
               continue;
            }
            char n=filePath[index+1];
            if (n=='/') {
               index++; continue;
            }
            if (n=='.') {
               if (index+2>=len) {
                  index++;
                  string::size_type split=result.rfind('/',result.length()-2);
                  if (split!=string::npos) {
                     if (result.substr(split)!="/../")
                        result.resize(split);
                  } else if (result.length()>0) {
                     if ((result!="../")&&(result!="/")) result.clear();
                  } else result="..";
                  continue;
               } else {
                  n=filePath[index+2];
                  if (n=='/') {
                     index+=2;
                     string::size_type split=result.rfind('/',result.length()-2);
                     if (split!=string::npos) {
                        if (result.substr(split)!="/../")
                           result.resize(split+1);
                     } else if (result.length()>0) {
                        if ((result!="../")&&(result!="/")) result.clear();
                     } else result="../";
                     continue;
                  }
               }
            }
         }
         result+=c; hadSep=false;
      }
   }
   return result;
}
//---------------------------------------------------------------------------
static bool readDwarfLineNumbers(const string& fileName,map<string,vector<pair<unsigned,void*> > >& lines)
   // Return the line numbers from dwarf informations
{
   // Open The file
   int fd=open(fileName.c_str(),O_RDONLY);
   if (fd<0) return false;

   // Initialize libdwarf
   Dwarf_Debug dbg;
   int status = dwarf_init(fd, DW_DLC_READ,dwarfErrorHandler,0,&dbg,0);
   if (status==DW_DLV_ERROR) { close(fd); return false; }
   if (status==DW_DLV_NO_ENTRY) { close(fd); return true; }

   // Iterator over the headers
   Dwarf_Unsigned header;
   while (dwarf_next_cu_header(dbg,0,0,0,0,&header,0)==DW_DLV_OK) {
      // Access the die
      Dwarf_Die die;
      if (dwarf_siblingof(dbg,0,&die,0)!=DW_DLV_OK)
         return false;

      // Get the source lines
      Dwarf_Line* lineBuffer;
      Dwarf_Signed lineCount;
      if (dwarf_srclines(die,&lineBuffer,&lineCount,0)!=DW_DLV_OK)
         continue; //return false;

      // Store them
      for (int index=0;index<lineCount;index++) {
         Dwarf_Unsigned lineNo;
         if (dwarf_lineno(lineBuffer[index],&lineNo,0)!=DW_DLV_OK)
            return false;
         char* lineSource;
         if (dwarf_linesrc(lineBuffer[index],&lineSource,0)!=DW_DLV_OK)
            return false;
         Dwarf_Bool isCode;
         if (dwarf_linebeginstatement(lineBuffer[index],&isCode,0)!=DW_DLV_OK)
            return false;
         Dwarf_Addr addr;
         if (dwarf_lineaddr(lineBuffer[index],&addr,0)!=DW_DLV_OK)
            return false;

         if (lineNo&&isCode) {
            lines[normalize(lineSource)].push_back(pair<unsigned,void*>(lineNo,reinterpret_cast<void*>(addr)));
         }

         dwarf_dealloc(dbg,lineSource,DW_DLA_STRING);
      }

      // Release the memory
      for (int index=0;index<lineCount;index++)
         dwarf_dealloc(dbg,lineBuffer[index],DW_DLA_LINE);
      dwarf_dealloc(dbg,lineBuffer,DW_DLA_LIST);
   }

   // Shut down libdwarf
   if (dwarf_finish(dbg,0)!=DW_DLV_OK)
      return false;

   close(fd);
   return true;
}
//---------------------------------------------------------------------------
static string escapeString(const string& s)
   // Escape string characters
{
   string result;
   for (string::const_iterator iter=s.begin(),limit=s.end();iter!=limit;++iter) {
      char c=(*iter);
      switch (c) {
         case '\\': result+="\\\\"; break;
         case '\n': result+="\\n"; break;
         case ' ': result+="\\ "; break;
         default: result+=c;
      }
   }
   return result;
}
//---------------------------------------------------------------------------
static bool dumpResult(const string& outputfile,const string& command,const vector<string>& args,const string& timestamp,const map<string,vector<pair<unsigned,void*> > >& activeLines,const map<void*,Debugger::BreakpointInfo>& activeAddresses)
   // Dump the results into a file
{
   ofstream out(outputfile.c_str());
   if (!out.is_open()) {
      cerr << "unable to write " << outputfile << endl;
      return false;
   }
   // Write the command information
   out << "command " << escapeString(command) << endl;
   out << "args";
   for (vector<string>::const_iterator iter=args.begin(),limit=args.end();iter!=limit;++iter)
      out << " " << escapeString(*iter);
   out << endl;
   out << "date " << timestamp << endl;
   // Process the files
   map<void*,Debugger::BreakpointInfo>::const_iterator limit4=activeAddresses.end();
   for (map<string,vector<pair<unsigned,void*> > >::const_iterator iter=activeLines.begin(),limit=activeLines.end();iter!=limit;++iter) {
      // Construct mapped represenation
      map<unsigned,set<void*> > addressesPerLine;
      for (vector<pair<unsigned,void*> >::const_iterator iter2=(*iter).second.begin(),limit2=(*iter).second.end();iter2!=limit2;++iter2)
         addressesPerLine[(*iter2).first].insert((*iter2).second);
      // Write hit info
      out << "file " << (*iter).first << endl;
      for (map<unsigned,set<void*> >::const_iterator iter2=addressesPerLine.begin(),limit2=addressesPerLine.end();iter2!=limit2;++iter2) {
         // Count the hits
         unsigned hits=0;
         for (set<void*>::const_iterator iter3=(*iter2).second.begin(),limit3=(*iter2).second.end();iter3!=limit3;++iter3) {
            map<void*,Debugger::BreakpointInfo>::const_iterator iter4=activeAddresses.find(*iter3);
            if (iter4==limit4) continue;
            if ((*iter4).second.hits) hits++;
         }
         // Write the status line
         out << (*iter2).first << " " << (*iter2).second.size() << " " << hits << endl;
      }
   }

   return true;
}
//---------------------------------------------------------------------------
static void showHelp(const char* argv0)
   // Show the help
{
   cout << "usage: " << argv0 << " [-o dump] command [arg(s)]" << endl;
}
//---------------------------------------------------------------------------
int main(int argc,char* argv[])
{
   // Parse the command line
   int start=1;
   string outputfile=".bcovdump";
   while (start<argc) {
      if (argv[start][0]=='-') {
         if (strcmp(argv[start],"--help")==0) {
            showHelp(argv[0]);
            return 1;
         }
         if (argv[start][1]=='o') {
            if (argv[start][2])
               outputfile=argv[start]+2; else
               outputfile=argv[++start];
         } else break;
      } else break;
   }
   if (start>=argc) {
      showHelp(argv[0]);
      return 1;
   }
   time_t now=time(0);
   string timestamp=ctime(&now);
   string command=argv[start];
   vector<string> args;
   for (int index=start+1;index<argc;index++)
      args.push_back(argv[index]);

   // Open the debugger
   Debugger dbg;
   if (!dbg.load(command,args)) {
      cerr << "unable to load " << command << endl;
      return 1;
   }

   // Find active lines
   cout << "probing debug information..." << endl;
   map<string,vector<pair<unsigned,void*> > > activeLines;
   if (!readDwarfLineNumbers(command,activeLines)) {
      cerr << "unable to read dwarf2 debug info" << endl;
      return 1;
   }
   cout << "found active lines in " << activeLines.size() << " source files" << endl;

   // Set breakpoints
   map<void*,Debugger::BreakpointInfo> activeAddresses;
   for (map<string,vector<pair<unsigned,void*> > >::const_iterator iter=activeLines.begin(),limit=activeLines.end();iter!=limit;++iter) {
      // Collect all addresses
      for (vector<pair<unsigned,void*> >::const_iterator iter2=(*iter).second.begin(),limit2=(*iter).second.end();iter2!=limit2;++iter2)
         activeAddresses[(*iter2).second];
   }
   // Set the breakpoints
   if (!dbg.setBreakpoints(activeAddresses)) {
      cerr << "unable to set breakpoints" << endl;
      return false;
   }
   cout << "set " << activeAddresses.size() << " breakpoints" << endl;

   // And execute
   bool stop=false;
   while (!stop) {
      Debugger::Event e=dbg.run();
      switch (e) {
         case Debugger::Error: cerr << "error encountered while tracing" << endl; stop=true; break;
         case Debugger::Exit: cerr << "program terminated" << endl; stop=true; break;
         case Debugger::Trap: {
            void* bpLocation = dbg.getIPBeforeTrap();
            // A unknown trap? Could be a hard-coded one, ignore it
            if (!activeAddresses.count(bpLocation)) continue;
            // Remove the breakpoint
            Debugger::BreakpointInfo& i=activeAddresses[bpLocation];
            dbg.eliminateHitBreakpoint(i);
            i.hits++;
            } break;
      }
   }

   // Close the debugger
   if (!dbg.close()) {
      cerr << "unable to close the debugger" << endl;
      return 1;
   }

   // Dump it
   dumpResult(outputfile,command,args,timestamp,activeLines,activeAddresses);
   cerr << "coverage info written to " << outputfile << endl;

   return 0;
}
//---------------------------------------------------------------------------
