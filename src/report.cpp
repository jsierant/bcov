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
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <cstdlib>
#include <cstring>
//---------------------------------------------------------------------------
using namespace std;
//---------------------------------------------------------------------------
/// The complete run information
struct RunInfo
{
   private:
   /// Coverage information about a line
   struct LineInfo {
      /// Number of possible hits
      unsigned hitsPossible;
      /// Number of encountered hits
      unsigned hits;
   };
   /// Coverage information about a file
   struct FileInfo
   {
      /// The lines
      map<unsigned,LineInfo> lines;
      /// Line summary
      unsigned totalLines,hitLines;
      /// Execution point summary
      unsigned totalStatements,hitStatements;
   };
   /// Coverage information about a directory
   struct DirInfo
   {
      /// The files
      map<string,FileInfo> files;
      /// Line summary
      unsigned totalLines,hitLines;
      /// Execution point summary
      unsigned totalStatements,hitStatements;
   };

   /// The command
   string command;
   /// The arguments
   string args;
   /// The timestamp
   string timestamp;
   /// The directories
   map<string,DirInfo> dirs;

   /// Update the aggregated statistics
   void updateStatistics();

   /// Write used png images
   bool writePNGs(const string& outputDirectory);
   /// Write the CSS file
   bool writeCSS(const string& outputDirectory);
   /// Write the header
   void writeHeader(ofstream& out,const string& title,const string& viewString,unsigned totalLines,unsigned hitLines,unsigned totalStatements,unsigned hitStatements);
   /// Write the footer
   void writeFooter(ofstream& out);
   /// Write a file report
   bool writeFileReport(const string& outputDirectory,const string& fileName,const FileInfo& fileInfo,const string& dirName,unsigned dirCounter,unsigned& fileCounter);
   /// Write a directory report
   bool writeDirectoryReport(const string& outputDirectory,const string& dirName,const DirInfo& dirInfo,unsigned& dirCounter,unsigned& fileCounter);

   public:
   /// Read it
   bool read(const string& file,const string& filterPath);
   /// Write the report
   bool writeReport(const string& outputDirectory);
   /// Delete a written report
   void removeReport(const string& outputDirectory);
};
//---------------------------------------------------------------------------
static void splitFileName(const string& s,string& dir,string& name)
   // Split a file name
{
   if (s.rfind('/')==string::npos) {
      dir="";
      name=s;
   } else {
      dir=s.substr(0,s.rfind('/')+1);
      name=s.substr(s.rfind('/')+1);
   }
}
//---------------------------------------------------------------------------
static void split(const string& s,vector<string>& parts)
   // Split a string
{
   string delimiters=" ";
   parts.clear();
   string::size_type lastPos=s.find_first_not_of(delimiters,0);
   string::size_type pos=s.find_first_of(delimiters,lastPos);
   while ((string::npos!=pos)||(string::npos!=lastPos)) {
      parts.push_back(s.substr(lastPos,pos-lastPos));
      lastPos=s.find_first_not_of(delimiters,pos);
      pos=s.find_first_of(delimiters,lastPos);
   }
}
//---------------------------------------------------------------------------
void RunInfo::updateStatistics()
   // Update the aggregated statistics
{
   for (map<string,DirInfo>::iterator iter=dirs.begin(),limit=dirs.end();iter!=limit;++iter) {
      DirInfo& d=(*iter).second;
      d.totalLines=d.hitLines=d.totalStatements=d.hitStatements=0;
      for (map<string,FileInfo>::iterator iter2=d.files.begin(),limit2=d.files.end();iter2!=limit2;++iter2) {
         FileInfo& f=(*iter2).second;
         f.totalLines=f.hitLines=f.totalStatements=f.hitStatements=0;
         for (map<unsigned,LineInfo>::const_iterator iter3=f.lines.begin(),limit3=f.lines.end();iter3!=limit3;++iter3) {
            const LineInfo& l=(*iter3).second;
            f.totalLines++;
            if (l.hits) f.hitLines++;
            f.totalStatements+=l.hitsPossible;
            f.hitStatements+=l.hits;
         }
         d.totalLines+=f.totalLines;
         d.hitLines+=f.hitLines;
         d.totalStatements+=f.totalStatements;
         d.hitStatements+=f.hitStatements;
      }
   }
}
//---------------------------------------------------------------------------
bool RunInfo::read(const string& fileName,const string& filterPath)
   // Read the dump
{
   ifstream in(fileName.c_str());
   if (!in.is_open()) {
      cerr << "unable to open " << fileName << endl;
      return false;
   }
   command=args=timestamp="";
   dirs.clear();
   FileInfo* currentFile=0;
   while (!in.eof()) {
      // Read and strip the current line
      string currentLine;
      getline(in,currentLine);
      while (true) {
         unsigned l=currentLine.length();
         if (!l) break;
         char c=currentLine[l-1];
         if ((c!='\n')&&(c!='\r')&&(c!=' ')&&(c!='\t')) break;
         currentLine=currentLine.substr(0,l-1);
      }
      if (!currentLine.length()) continue;
      // Interpret header
      if (currentLine.compare(0,8,"command ")==0) { command=currentLine.substr(8); continue; }
      if (currentLine.compare(0,5,"args ")==0) { args=currentLine.substr(5); continue; }
      if (currentLine.compare(0,5,"date ")==0) { timestamp=currentLine.substr(5); continue; }
      if (currentLine.compare(0,5,"file ")==0) {
         string dir,name,path=currentLine.substr(5);
         // apply filter, set currentFile=0 when supressing
         if ((filterPath=="") || (path.compare(0,filterPath.length(),filterPath)==0)) {
            splitFileName(path,dir,name);
            currentFile=&(dirs[dir].files[name]);
         } else currentFile=0;
         continue;
      }
      // A regular line
      if (!currentFile) continue;
      vector<string> parts;
      split(currentLine,parts);
      if (parts.size()!=3) continue;
      LineInfo& line=currentFile->lines[atoi(parts[0].c_str())];
      line.hitsPossible=atoi(parts[1].c_str());
      line.hits=atoi(parts[2].c_str());
   }
   updateStatistics();
   return true;
}
//---------------------------------------------------------------------------
static string itoa(int i)
   // Integer as string
{
   char buffer[30];
   snprintf(buffer,sizeof(buffer),"%d",i);
   return string(buffer);
}
//---------------------------------------------------------------------------
static bool writeBLOB(const string& fileName,const char* data,unsigned len)
   // Write binary data to a file
{
   ofstream out(fileName.c_str(), ios::out | ios::binary);
   if (!out.is_open()) {
      cerr << "unable to write " << fileName << endl;
      return false;
   }
   out.write(data,len);
   return true;
}
//---------------------------------------------------------------------------
bool RunInfo::writePNGs(const string& outputDirectory)
   // Write used png images
{
   static const char ruby[] = { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x25, 0xdb, 0x56, 0xca, 0x00, 0x00, 0x00, 0x07, 0x74, 0x49, 0x4d, 0x45, 0x07, 0xd2, 0x07, 0x11, 0x0f, 0x18, 0x10, 0x5d, 0x57, 0x34, 0x6e, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0b, 0x12, 0x00, 0x00, 0x0b, 0x12, 0x01, 0xd2, 0xdd, 0x7e, 0xfc, 0x00, 0x00, 0x00, 0x04, 0x67, 0x41, 0x4d, 0x41, 0x00, 0x00, 0xb1, 0x8f, 0x0b, 0xfc, 0x61, 0x05, 0x00, 0x00, 0x00, 0x06, 0x50, 0x4c, 0x54, 0x45, 0xff, 0x35, 0x2f, 0x00, 0x00, 0x00, 0xd0, 0x33, 0x9a, 0x9d, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xe5, 0x27, 0xde, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };
   static const char amber[] = { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x25, 0xdb, 0x56, 0xca, 0x00, 0x00, 0x00, 0x07, 0x74, 0x49, 0x4d, 0x45, 0x07, 0xd2, 0x07, 0x11, 0x0f, 0x28, 0x04, 0x98, 0xcb, 0xd6, 0xe0, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0b, 0x12, 0x00, 0x00, 0x0b, 0x12, 0x01, 0xd2, 0xdd, 0x7e, 0xfc, 0x00, 0x00, 0x00, 0x04, 0x67, 0x41, 0x4d, 0x41, 0x00, 0x00, 0xb1, 0x8f, 0x0b, 0xfc, 0x61, 0x05, 0x00, 0x00, 0x00, 0x06, 0x50, 0x4c, 0x54, 0x45, 0xff, 0xe0, 0x50, 0x00, 0x00, 0x00, 0xa2, 0x7a, 0xda, 0x7e, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xe5, 0x27, 0xde, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };
   static const char emerald[] = { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x25, 0xdb, 0x56, 0xca, 0x00, 0x00, 0x00, 0x07, 0x74, 0x49, 0x4d, 0x45, 0x07, 0xd2, 0x07, 0x11, 0x0f, 0x22, 0x2b, 0xc9, 0xf5, 0x03, 0x33, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0b, 0x12, 0x00, 0x00, 0x0b, 0x12, 0x01, 0xd2, 0xdd, 0x7e, 0xfc, 0x00, 0x00, 0x00, 0x04, 0x67, 0x41, 0x4d, 0x41, 0x00, 0x00, 0xb1, 0x8f, 0x0b, 0xfc, 0x61, 0x05, 0x00, 0x00, 0x00, 0x06, 0x50, 0x4c, 0x54, 0x45, 0x1b, 0xea, 0x59, 0x0a, 0x0a, 0x0a, 0x0f, 0xba, 0x50, 0x83, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xe5, 0x27, 0xde, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };
   static const char snow[] = { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x25, 0xdb, 0x56, 0xca, 0x00, 0x00, 0x00, 0x07, 0x74, 0x49, 0x4d, 0x45, 0x07, 0xd2, 0x07, 0x11, 0x0f, 0x1e, 0x1d, 0x75, 0xbc, 0xef, 0x55, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0b, 0x12, 0x00, 0x00, 0x0b, 0x12, 0x01, 0xd2, 0xdd, 0x7e, 0xfc, 0x00, 0x00, 0x00, 0x04, 0x67, 0x41, 0x4d, 0x41, 0x00, 0x00, 0xb1, 0x8f, 0x0b, 0xfc, 0x61, 0x05, 0x00, 0x00, 0x00, 0x06, 0x50, 0x4c, 0x54, 0x45, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x55, 0xc2, 0xd3, 0x7e, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0xda, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0xe5, 0x27, 0xde, 0xfc, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };
   static const char glass[] = { 0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x03, 0x00, 0x00, 0x00, 0x25, 0xdb, 0x56, 0xca, 0x00, 0x00, 0x00, 0x04, 0x67, 0x41, 0x4d, 0x41, 0x00, 0x00, 0xb1, 0x8f, 0x0b, 0xfc, 0x61, 0x05, 0x00, 0x00, 0x00, 0x06, 0x50, 0x4c, 0x54, 0x45, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x55, 0xc2, 0xd3, 0x7e, 0x00, 0x00, 0x00, 0x01, 0x74, 0x52, 0x4e, 0x53, 0x00, 0x40, 0xe6, 0xd8, 0x66, 0x00, 0x00, 0x00, 0x01, 0x62, 0x4b, 0x47, 0x44, 0x00, 0x88, 0x05, 0x1d, 0x48, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0b, 0x12, 0x00, 0x00, 0x0b, 0x12, 0x01, 0xd2, 0xdd, 0x7e, 0xfc, 0x00, 0x00, 0x00, 0x07, 0x74, 0x49, 0x4d, 0x45, 0x07, 0xd2, 0x07, 0x13, 0x0f, 0x08, 0x19, 0xc4, 0x40, 0x56, 0x10, 0x00, 0x00, 0x00, 0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x48, 0xaf, 0xa4, 0x71, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82 };

   if (!writeBLOB(outputDirectory+"/ruby.png",ruby,sizeof(ruby))) return false;
   if (!writeBLOB(outputDirectory+"/amber.png",amber,sizeof(amber))) return false;
   if (!writeBLOB(outputDirectory+"/emerald.png",emerald,sizeof(emerald))) return false;
   if (!writeBLOB(outputDirectory+"/snow.png",snow,sizeof(snow))) return false;
   if (!writeBLOB(outputDirectory+"/glass.png",glass,sizeof(glass))) return false;

   return true;
}
//---------------------------------------------------------------------------
bool RunInfo::writeCSS(const string& outputDirectory)
   // Write the CSS file
{
   string outputFile=outputDirectory+"/bcov.css";
   ofstream out(outputFile.c_str());
   if (!out.is_open()) {
      cerr << "unable to write " << outputFile << endl;
      return false;
   }
   out << "/* Based upon the lcov CSS style, style files can be reused */" << endl
       << "body { color: #000000; background-color: #FFFFFF; }" << endl
       << "a:link { color: #284FA8; text-decoration: underline; }" << endl
       << "a:visited { color: #00CB40; text-decoration: underline; }" << endl
       << "a:active { color: #FF0040; text-decoration: underline; }" << endl
       << "td.title { text-align: center; padding-bottom: 10px; font-size: 20pt; font-weight: bold; }" << endl
       << "td.ruler { background-color: #6688D4; }" << endl
       << "td.headerItem { text-align: right; padding-right: 6px; font-family: sans-serif; font-weight: bold; }" << endl
       << "td.headerValue { text-align: left; color: #284FA8; font-family: sans-serif; font-weight: bold; }" << endl
       << "td.versionInfo { text-align: center; padding-top:  2px; }" << endl
       << "pre.source { font-family: monospace; white-space: pre; }" << endl
       << "span.lineNum { background-color: #EFE383; }" << endl
       << "span.lineCov { background-color: #CAD7FE; }" << endl
       << "span.linePartCov { background-color: #FFEA20; }" << endl
       << "span.lineNoCov { background-color: #FF6230; }" << endl
       << "td.tableHead { text-align: center; color: #FFFFFF; background-color: #6688D4; font-family: sans-serif; font-size: 120%; font-weight: bold; }" << endl
       << "td.coverFile { text-align: left; padding-left: 10px; padding-right: 20px; color: #284FA8; background-color: #DAE7FE; font-family: monospace; }" << endl
       << "td.coverBar { padding-left: 10px; padding-right: 10px; background-color: #DAE7FE; }" << endl
       << "td.coverBarOutline { background-color: #000000; }" << endl
       << "td.coverPerHi { text-align: right; padding-left: 10px; padding-right: 10px; background-color: #A7FC9D; font-weight: bold; }" << endl
       << "td.coverNumHi { text-align: right; padding-left: 10px; padding-right: 10px; background-color: #A7FC9D; }" << endl
       << "td.coverPerMed { text-align: right; padding-left: 10px; padding-right: 10px; background-color: #FFEA20; font-weight: bold; }" << endl
       << "td.coverNumMed { text-align: right; padding-left: 10px; padding-right: 10px; background-color: #FFEA20; }" << endl
       << "td.coverPerLo { text-align: right; padding-left: 10px; padding-right: 10px; background-color: #FF0000; font-weight: bold; }" << endl
       << "td.coverNumLo { text-align: right; padding-left: 10px; padding-right: 10px; background-color: #FF0000; }" << endl
       ;
   return true;
}
//---------------------------------------------------------------------------
static string escapeHtml(const string& s)
   // Escape a string for html
{
   string result;
   for (string::const_iterator iter=s.begin(),limit=s.end();iter!=limit;++iter) {
      char c=*iter;
      if ((c&0xFF)>127) {
         result+="&#"; result+=itoa(c&0xFF); result+=";";
      } else {
         switch (c) {
            case '<': result+="&lt;"; break;
            case '>': result+="&gt;"; break;
            case '&': result+="&amp;"; break;
            case '\"': result+="&quot;"; break;
            case '\n': case '\r': result+" "; break;
            default: result+=c;
         }
      }
   }
   return result;
}
//---------------------------------------------------------------------------
void RunInfo::writeHeader(ofstream& out,const string& title,const string& viewString,unsigned totalLines,unsigned hitLines,unsigned totalStatements,unsigned hitStatements)
   // Write the header
{
   char covered[20];
   snprintf(covered,sizeof(covered),"%.1f",(!totalLines)?0.0:(static_cast<double>(100*hitLines)/totalLines));
   out << "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">" << endl
       << "<html>" << endl
       << "<head>" << endl
       << "  <title>Coverage - " << escapeHtml(command) << " - " << escapeHtml(title) << "</title>" << endl
       << "  <link rel=\"stylesheet\" type=\"text/css\" href=\"bcov.css\"/>" << endl
       << "</head>" << endl
       << "<body>" << endl
       << "<table width=\"100%\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">" << endl
       << "  <tr><td class=\"title\">Coverage Report</td></tr>" << endl
       << "  <tr><td class=\"ruler\"><img src=\"glass.png\" width=\"3\" height=\"3\" alt=\"\"/></td></tr>" << endl
       << "  <tr>" << endl
       << "    <td width=\"100%\">" << endl
       << "      <table cellpadding=\"1\" border=\"0\" width=\"100%\">" << endl
       << "        <tr>" << endl
       << "          <td class=\"headerItem\" width=\"20%\">Current&nbsp;view:</td>" << endl
       << "          <td class=\"headerValue\" width=\"80%\" colspan=6>" << viewString << "</td>" << endl
       << "        </tr>" << endl
       << "        <tr>" << endl
       << "          <td class=\"headerItem\" width=\"20%\">Command:</td>" << endl
       << "          <td class=\"headerValue\" width=\"80%\" colspan=6>" << escapeHtml(command) << " " << escapeHtml(args) << "</td>" << endl
       << "        </tr>" << endl
       << "        <tr>" << endl
       << "          <td class=\"headerItem\" width=\"20%\">Date:</td>" << endl
       << "          <td class=\"headerValue\" width=\"15%\">" << escapeHtml(timestamp) << "</td>" << endl
       << "          <td width=\"5%\"></td>" << endl
       << "          <td class=\"headerItem\" width=\"20%\">Instrumented&nbsp;lines:</td>" << endl
       << "          <td class=\"headerValue\" width=\"10%\">" << itoa(totalLines) << "</td>" << endl
       << "          <td class=\"headerItem\" width=\"20%\">Instrumented&nbsp;statements:</td>" << endl
       << "          <td class=\"headerValue\" width=\"10%\">" << itoa(totalStatements) << "</td>" << endl
       << "        </tr>" << endl
       << "        <tr>" << endl
       << "          <td class=\"headerItem\" width=\"20%\">Code&nbsp;covered:</td>" << endl
       << "          <td class=\"headerValue\" width=\"15%\">" << covered << " %</td>" << endl
       << "          <td width=\"5%\"></td>" << endl
       << "          <td class=\"headerItem\" width=\"20%\">Executed&nbsp;lines:</td>" << endl
       << "          <td class=\"headerValue\" width=\"10%\">" << itoa(hitLines) << "</td>" << endl
       << "          <td class=\"headerItem\" width=\"20%\">Executed&nbsp;statements:</td>" << endl
       << "          <td class=\"headerValue\" width=\"10%\">" << itoa(hitStatements) << "</td>" << endl
       << "        </tr>" << endl
       << "      </table>" << endl
       << "    </td>" << endl
       << "  </tr>" << endl
       << "  <tr><td class=\"ruler\"><img src=\"glass.png\" width=\"3\" height=\"3\" alt=\"\"/></td></tr>" << endl
       << "</table>" << endl;
}
//---------------------------------------------------------------------------
void RunInfo::writeFooter(ofstream& out)
   // Write the footer
{
   out << "<table width=\"100%\" border=\"0\" cellspacing=\"0\" cellpadding=\"0\">" << endl
       << "  <tr><td class=\"ruler\"><img src=\"glass.png\" width=\"3\" height=\"3\" alt=\"\"/></td></tr>" << endl
       << "  <tr><td class=\"versionInfo\">Generated by: <a href=\"http://bcov.sourceforge.net\">bcov</a></td></tr>" << endl
       << "</table>" << endl
       << "<br/>" << endl
       << "</body>" << endl
       << "</html>" << endl;
}
//---------------------------------------------------------------------------
bool RunInfo::writeFileReport(const string& outputDirectory,const string& fileName,const FileInfo& fileInfo,const string& dirName,unsigned dirCounter,unsigned& fileCounter)
   // Write a file report
{
   string outName=outputDirectory+"/file"+itoa(fileCounter++)+".html";
   ofstream out(outName.c_str());
   if (!out.is_open()) {
      cerr << "unable to write " << outName << endl;
      return false;
   }

   // Write the header
   string fullName = dirName+"/"+fileName;
   string view = "<a href=\"index.html\">directory</a> - <a href=\"dir"+itoa(dirCounter)+".html\">"+escapeHtml(dirName)+"</a> - "+escapeHtml(fileName);
   writeHeader(out,fullName,view,fileInfo.totalLines,fileInfo.hitLines,fileInfo.totalStatements,fileInfo.hitStatements);

   // Write the file itself
   ifstream in(fullName.c_str());
   if (!in.is_open()) {
      out << "<br/><h4>No source code found!</h4><br/>" << endl;
   } else {
      out << "<pre class=\"source\">" << endl;
      unsigned lineNo=0;
      while (!in.eof()) {
         // Read and strip the current line
         string currentLine;
         getline(in,currentLine);
         if ((!currentLine.length())&&(in.eof())) break;
         while (true) {
            unsigned l=currentLine.length();
            if (!l) break;
            char c=currentLine[l-1];
            if ((c!='\n')&&(c!='\r')&&(c!=' ')&&(c!='\t')) break;
            currentLine=currentLine.substr(0,l-1);
         }
         // Write the line number
         char buffer[50];
         snprintf(buffer,sizeof(buffer),"%8u ",++lineNo);
         out << "<span class=\"lineNum\">" << buffer << "</span>";
         // Write the hit information
         map<unsigned,LineInfo>::const_iterator iter=fileInfo.lines.find(lineNo);
         if (iter==fileInfo.lines.end()) {
            out << "            ";
         } else {
            if ((*iter).second.hits==(*iter).second.hitsPossible)
               out << "<span class=\"lineCov\">"; else
            if ((*iter).second.hits)
               out << "<span class=\"linePartCov\">"; else
               out << "<span class=\"lineNoCov\">";
            snprintf(buffer,sizeof(buffer),"%u / %u ",(*iter).second.hits,(*iter).second.hitsPossible);
            for (unsigned index=strlen(buffer);index<12;index++)
               out << " ";
            out << buffer;
         }
         // Write the line itself
         out << " : ";
         out << escapeHtml(currentLine);
         if (iter!=fileInfo.lines.end())
            out << "</span>";
         out << endl;
      }
      out << "</pre>" << endl;
   }

   // Write the footer
   writeFooter(out);

   return true;
}
//---------------------------------------------------------------------------
static string constructBar(double percent)
   // Construct a percentage bar
{
   const char* color;
   if (percent>=50) color="emerald.png"; else
   if (percent>=15) color="amber.png"; else
      color="ruby.png";
   int width=static_cast<int>(percent+0.5);

   char buffer[200];
   if (width<1) {
      snprintf(buffer,sizeof(buffer),"<img src=\"snow.png\" width=\"%d\" height=\"10\" alt=\"%.1f%%\"/>",100,0.0);
   } else if (width>=100) {
      snprintf(buffer,sizeof(buffer),"<img src=\"%s\" width=\"%d\" height=\"10\" alt=\"%.1f%%\"/>",color,100,100.0);
   } else {
      snprintf(buffer,sizeof(buffer),"<img src=\"%s\" width=\"%d\" height=\"10\" alt=\"%.1f%%\"/><img src=\"snow.png\" width=\"%d\" height=\"10\" alt=\"%.1f%%\"/>",color,width,percent,100-width,percent);
   }
   return string(buffer);
}
//---------------------------------------------------------------------------
bool RunInfo::writeDirectoryReport(const string& outputDirectory,const string& dirName,const DirInfo& dirInfo,unsigned& dirCounter,unsigned& fileCounter)
   // Write a directory report
{
   // Write the files first
   unsigned fileId=fileCounter;
   for (map<string,FileInfo>::const_iterator iter=dirInfo.files.begin(),limit=dirInfo.files.end();iter!=limit;++iter)
      if (!writeFileReport(outputDirectory,(*iter).first,(*iter).second,dirName,dirCounter,fileCounter))
         return false;

   // Now write the directory page
   string outName=outputDirectory+"/dir"+itoa(dirCounter++)+".html";
   ofstream out(outName.c_str());
   if (!out.is_open()) {
      cerr << "unable to write " << outName << endl;
      return false;
   }

   // Write the header
   string view = "<a href=\"index.html\">directory</a> - "+escapeHtml(dirName);
   writeHeader(out,dirName,view,dirInfo.totalLines,dirInfo.hitLines,dirInfo.totalStatements,dirInfo.hitStatements);

   // Now write the file summaries
   out << "<center>" << endl
       << "  <table width=\"80%\" cellpadding=\"2\" cellspacing=\"1\" border=\"0\">" << endl
       << "    <tr>" << endl
       << "      <td width=\"50%\"><br/></td>" << endl
       << "      <td width=\"15%\"></td>" << endl
       << "      <td width=\"15%\"></td>" << endl
       << "      <td width=\"20%\"></td>" << endl
       << "    </tr>" << endl
       << "    <tr>" << endl
       << "      <td class=\"tableHead\">Filename</td>" << endl
       << "      <td class=\"tableHead\" colspan=\"3\">Coverage</td>" << endl
       << "    </tr>" << endl;
   for (map<string,FileInfo>::const_iterator iter=dirInfo.files.begin(),limit=dirInfo.files.end();iter!=limit;++iter) {
      double percentage=(*iter).second.totalLines?(static_cast<double>(100*(*iter).second.hitLines)/(*iter).second.totalLines):0.0;
      string qc;
      if (percentage>=50) qc="Hi"; else
      if (percentage>=15) qc="Med"; else
         qc="Lo";
      char percentageText[40];
      snprintf(percentageText,sizeof(percentageText),"%.1f",percentage);
      out
       << "    <tr>" << endl
       << "      <td class=\"coverFile\"><a href=\"file"+itoa(fileId++)+".html\">"+escapeHtml((*iter).first)+"</a></td>" << endl
       << "      <td class=\"coverBar\" align=\"center\">" << endl
       << "        <table border=\"0\" cellspacing=\"0\" cellpadding=\"1\"><tr><td class=\"coverBarOutline\">" << constructBar(percentage) << "</td></tr></table>" << endl
       << "      </td>" << endl
       << "      <td class=\"coverPer" << qc << "\">" << percentageText << "&nbsp;%</td>" << endl
       << "      <td class=\"coverNum" << qc << "\">" << (*iter).second.hitLines << "&nbsp;/&nbsp;" << (*iter).second.totalLines << "&nbsp;lines</td>" << endl
       << "    </tr>" << endl;
   }
   out << "  </table>" << endl
       << "</center>" << endl
       << "<br/>" << endl;

   // Write the footer
   writeFooter(out);

   return true;
}
//---------------------------------------------------------------------------
bool RunInfo::writeReport(const string& outputDirectory)
   // Write the report
{
   // Dump the helper files
   if ((!writeCSS(outputDirectory))||(!writePNGs(outputDirectory)))
      return false;

   // Write the directories first
   unsigned dirCounter=0,fileCounter=0;
   unsigned totalLines=0,hitLines=0,totalStatements=0,hitStatements=0;
   for (map<string,DirInfo>::const_iterator iter=dirs.begin(),limit=dirs.end();iter!=limit;++iter) {
      if (!writeDirectoryReport(outputDirectory,(*iter).first,(*iter).second,dirCounter,fileCounter))
         return false;
      totalLines+=(*iter).second.totalLines;
      hitLines+=(*iter).second.hitLines;
      totalStatements+=(*iter).second.totalStatements;
      hitStatements+=(*iter).second.hitStatements;
   }

   // Now write the index page
   string outName=outputDirectory+"/index.html";
   ofstream out(outName.c_str());
   if (!out.is_open()) {
      cerr << "unable to write " << outName << endl;
      return false;
   }

   // Write the header
   string view = "directory";
   writeHeader(out,"",view,totalLines,hitLines,totalStatements,hitStatements);

   // Now write the file summaries
   dirCounter=0;
   out << "<center>" << endl
       << "  <table width=\"80%\" cellpadding=\"2\" cellspacing=\"1\" border=\"0\">" << endl
       << "    <tr>" << endl
       << "      <td width=\"50%\"><br/></td>" << endl
       << "      <td width=\"15%\"></td>" << endl
       << "      <td width=\"15%\"></td>" << endl
       << "      <td width=\"20%\"></td>" << endl
       << "    </tr>" << endl
       << "    <tr>" << endl
       << "      <td class=\"tableHead\">Directory</td>" << endl
       << "      <td class=\"tableHead\" colspan=\"3\">Coverage</td>" << endl
       << "    </tr>" << endl;
   for (map<string,DirInfo>::const_iterator iter=dirs.begin(),limit=dirs.end();iter!=limit;++iter) {
      string dirName=(*iter).first;
      if (dirName=="") dirName=".";
      double percentage=(*iter).second.totalLines?(static_cast<double>(100*(*iter).second.hitLines)/(*iter).second.totalLines):0.0;
      string qc;
      if (percentage>=50) qc="Hi"; else
      if (percentage>=15) qc="Med"; else
         qc="Lo";
      char percentageText[40];
      snprintf(percentageText,sizeof(percentageText),"%.1f",percentage);
      out
       << "    <tr>" << endl
       << "      <td class=\"coverFile\"><a href=\"dir"+itoa(dirCounter++)+".html\">"+escapeHtml(dirName)+"</a></td>" << endl
       << "      <td class=\"coverBar\" align=\"center\">" << endl
       << "        <table border=\"0\" cellspacing=\"0\" cellpadding=\"1\"><tr><td class=\"coverBarOutline\">" << constructBar(percentage) << "</td></tr></table>" << endl
       << "      </td>" << endl
       << "      <td class=\"coverPer" << qc << "\">" << percentageText << "&nbsp;%</td>" << endl
       << "      <td class=\"coverNum" << qc << "\">" << (*iter).second.hitLines << "&nbsp;/&nbsp;" << (*iter).second.totalLines << "&nbsp;lines</td>" << endl
       << "    </tr>" << endl;
   }
   out << "  </table>" << endl
       << "</center>" << endl
       << "<br/>" << endl;

   // Write the footer
   writeFooter(out);

   return true;
}
//---------------------------------------------------------------------------
static void removeFile(const string& dir,const string& name)
   // Remove a file
{
   string fullName=dir+"/"+name;
   unlink(fullName.c_str());
}
//---------------------------------------------------------------------------
void RunInfo::removeReport(const string& outputDirectory)
   // Delete a written report
{
   // Remove helper files first
   removeFile(outputDirectory,"bcov.css");
   removeFile(outputDirectory,"ruby.png");
   removeFile(outputDirectory,"amber.png");
   removeFile(outputDirectory,"emerald.png");
   removeFile(outputDirectory,"snow.png");
   removeFile(outputDirectory,"glass.png");

   // Remove all sub pages
   unsigned dirCounter=0,fileCounter=0;
   for (map<string,DirInfo>::const_iterator iter=dirs.begin(),limit=dirs.end();iter!=limit;++iter) {
      for (unsigned files=(*iter).second.files.size();files;--files)
         removeFile(outputDirectory,"file"+itoa(fileCounter++)+".html");
      removeFile(outputDirectory,"dir"+itoa(dirCounter++)+".html");
   }

   // Remove the index page
   removeFile(outputDirectory,"index.html");
}
//---------------------------------------------------------------------------
static string tempDirectory()
   // Create a temporary directory
{
   char buffer[]="/tmp/bcov-report.XXXXXX";
   if (!mkdtemp(buffer)) {
      perror("mkdtemp");
      throw;
   }
   cerr << "writing coverage report to " << buffer << endl;
   return string(buffer);
}
//---------------------------------------------------------------------------
static void showHelp(const char* argv0)
   // Show the help
{
   cout << "usage: " << argv0 << "[-i path] [dumpfile [output directory]]" << endl
      << endl
      << "\t--help\t\tshow help and end" << endl
      << "\t--version\tshow the tool version and end" << endl
      << endl
      << "\t-i\t\tinclude files under given path in report (default /)" << endl;
}
//---------------------------------------------------------------------------
static void showVersion(const char* argv0)
   // Show the help
{
   cout << argv0 << " " << PACKAGE_VERSION " from package " << PACKAGE_TARNAME << endl;
}
//---------------------------------------------------------------------------
int main(int argc,char* argv[])
{
   // Parse the command line
   string inputFile=".bcovdump";
   string outputDirectory;
   string filterPath="";
   int start=1;
   while (start<argc) {
      if (argv[start][0]=='-') {
         if (strcmp(argv[start],"--help")==0) {
            showHelp(argv[0]);
            return 1;
         } else if (strcmp(argv[start],"--version")==0) {
            showVersion(argv[0]);
            return 1;
         } else if (argv[start][1]=='i') {
            char *path;
            if (argv[start][2])
               path=(argv[start]+2);
            else
               path=argv[++start];
            filterPath=realpath(path,0l);
            start++;
         } else break;
      } else break;
   }
   if (argc>start) {
      inputFile=argv[start];
      if (argc>(start+1)) outputDirectory=argv[start+1];
   }

   // Parse the input
   RunInfo run;
   if (!run.read(inputFile,filterPath))
      return 1;

   // Generate a temporary directory if needed
   bool temp=false;
   if (outputDirectory=="") {
      temp=true;
      outputDirectory=tempDirectory();
   }

   // Write the output
   run.writeReport(outputDirectory);

   // Show using the default browser if only temporary data
   if (temp&&getenv("DISPLAY")) {
      string command="x-www-browser file://"+outputDirectory+"/index.html";
      if (system(command.c_str())!=0) {
         cerr << "unable to launch " << command << endl;
         return 1;
      } else {
         cerr << "removing temporary directory. specify output directory to keep the results." << endl;
         run.removeReport(outputDirectory);
         rmdir(outputDirectory.c_str());
      }
   }
}
//---------------------------------------------------------------------------
