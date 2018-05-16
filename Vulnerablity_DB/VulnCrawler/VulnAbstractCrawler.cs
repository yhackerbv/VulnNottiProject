﻿using LibGit2Sharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace VulnCrawler
{
    // 추상 클래스
    public abstract class VulnAbstractCrawler
    {
        /// <summary>
        /// 생성자
        /// 경로를 입력받아서(path)
        /// 레파지토리를 초기화하고
        /// 커밋 목록을 검색함
        /// </summary>
        /// <param name="path"></param>
        public VulnAbstractCrawler() {

        }

        // 소멸자
        ~VulnAbstractCrawler() {

            Repository.Dispose();
        }

        protected virtual Regex MethodExtractor => new Regex(RegexFuncPattern);

        #region 메서드 패턴 정규식 그룹
        // 정규식 그룹화
        // @@ -oldStart,oldLines +newStart,newLines @@ MethodName():
        public static string OldStart => "oldStart";
        public static string OldLines => "oldLines";
        public static string NewStart => "newStart";
        public static string NewLines => "newLines";
        public static string MethodName => "methodName";
        #endregion

        public void Init(string path) {
            Repository = new Repository(path);
            Commits = SearchCommits();
        }
        /// <summary>
        /// 레파지토리
        /// </summary>
        public Repository Repository { get; private set; }

        /// <summary>
        /// 커밋 목록
        /// </summary>
        public IEnumerable<Commit> Commits { get; private set; }
        /// <summary>
        /// 커밋에서 검색할 정규식 문자열
        /// </summary>
        public string SearchCommitPattern => @"CVE-20\d\d-\d{4}";
        /// <summary>
        /// 패치 코드에서 함수 찾을 정규식 패턴 문자열
        /// </summary>
        protected abstract string RegexFuncPattern { get; }
        protected abstract string Extension { get; }
        public virtual IEnumerable<PatchEntryChanges> GetPatchEntryChanges(Patch patch) {
            return patch.Where(e => e.Path.EndsWith(Extension)).ToList();
        }
        /// <summary>
        /// 정규식을 이용하여 @@ -\d,\d +\d,\d @@ MethodName(): 이런 패턴을 찾고
        /// 그룹화 하여 반환함 (OldStart, OldLines, NewStart, NewLines, MethodName
        /// </summary>
        /// <param name="patchCode">찾을 코드</param>
        /// <returns>정규식 그룹 컬렉션</returns>
        public abstract MatchCollection GetMatches(string patchCode);
        /// <summary>
        /// 파일스트림으로 부터 원본 함수 구하는 함수
        /// </summary>
        /// <param name="oldStream">파일 스트림</param>
        /// <param name="methodName">찾을 메서드 이름</param>
        /// <returns>함수 문자열</returns>
        protected abstract string GetOriginalFunc(Stream oldStream, string methodName);


        /// <summary>
        /// 실제 프로세스
        /// </summary>
        /// <param name="oldStream"></param>
        /// <param name="methodName"></param>
        /// <returns></returns>
        public virtual (string originalFunc, string hash) Process(Stream oldStream, string methodName) {
            // 패치 전 원본 함수 구하고
            string func = GetOriginalFunc(oldStream, methodName);
            // 주석 제거하고
            func = RemoveComment(func);
            // 해쉬하고
            string md5 = MD5HashFunc(func);
            return (func, md5);
        }
        /// <summary>
        /// 주석 제거 함수
        /// </summary>
        /// <param name="original">제거할 문자열</param>
        /// <returns>결과 문자열</returns>
        public abstract string RemoveComment(string original);

        /// <summary>
        /// 커밋 검색 함수(정규식 사용)
        /// 정규식은 SearchKeyword 사용함
        /// </summary>
        /// <returns>커밋 목록</returns>
        public virtual IEnumerable<Commit> SearchCommits() {
            // where => 조건에 맞는 것을 찾음(CVE-20\d\d-\d{4}로 시작하는 커밋만 골라냄)
            var commits = Repository.Commits
                                    .Where(c => Regex.Match(c.Message, SearchCommitPattern, RegexOptions.IgnoreCase).Success)
                                    .ToList();

            return commits;
        }

        /// <summary>
        /// 커밋 메시지로부터 CVE 코드 추출
        /// </summary>
        /// <param name="msg"></param>
        /// <returns></returns>
        public string GetCVE(string msg) {
            var match = Regex.Match(msg, SearchCommitPattern, RegexOptions.IgnoreCase);

            if (match.Success) {
                return match.Value;
            }
            return string.Empty;
        }
        /// <summary>
        /// MD5 함수
        /// </summary>
        /// <param name="str">INPUT 문자열</param>
        /// <returns>결과 문자열</returns>
        protected static string MD5HashFunc(string str) {
            StringBuilder MD5Str = new StringBuilder();
            byte[] byteArr = Encoding.ASCII.GetBytes(str);
            byte[] resultArr = (new MD5CryptoServiceProvider()).ComputeHash(byteArr);
            for (int cnti = 0; cnti < resultArr.Length; cnti++) {
                MD5Str.Append(resultArr[cnti].ToString("X2"));
            }
            return MD5Str.ToString();
        }

    }
}
