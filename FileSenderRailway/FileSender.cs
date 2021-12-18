using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using ResultOf;

namespace FileSenderRailway
{
    public class FileSender
    {
        private readonly ICryptographer cryptographer;
        private readonly IRecognizer recognizer;
        private readonly Func<DateTime> now;
        private readonly ISender sender;

        public FileSender(
            ICryptographer cryptographer,
            ISender sender,
            IRecognizer recognizer,
            Func<DateTime> now)
        {
            this.cryptographer = cryptographer;
            this.sender = sender;
            this.recognizer = recognizer;
            this.now = now;
        }

        private Result<Document> PrepareToSend(Result<Document> doc, X509Certificate certificate)
        {
            return doc
                .Then(d => IsValidFormatVersion(d))
                .Then(d => IsValidTimestamp(d))
                .Then(d => d.ReplaceContent(cryptographer.Sign(d.Content, certificate)))
                .RefineError("Can't prepare file to send");
        }
        
        public IEnumerable<FileSendResult> SendFiles(FileContent[] files, X509Certificate certificate) => files.Select(file => new { file, doc = PrepareToSend(Result.Of(() => recognizer.Recognize(file)), certificate) }).Select(t => new FileSendResult(t.file, t.doc.Error ?? t.doc.Then(d => sender.Send(d)).RefineError("Can't send").Error));

        private Result<Document> IsValidFormatVersion(Result<Document> doc)
        {
            if (!doc.IsSuccess) return doc;
            var error = doc.Value.Format is "4.0" or "3.1" ? null : "Invalid format version";
            return new Result<Document>(error, doc.Value);
        }

        private Result<Document> IsValidTimestamp(Result<Document> doc)
        {
            if (!doc.IsSuccess) return doc;
            var error = doc.Value.Created > now().AddMonths(-1) ? null : "Too old document";
            return new Result<Document>(error, doc.Value);
        }
    }
}