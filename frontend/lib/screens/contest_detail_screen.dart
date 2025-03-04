import 'dart:io';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../models/contest.dart';
import '../models/comment.dart';
import 'package:http/http.dart' as http;

const String baseUrl = 'http://10.0.2.2:8080';

Future<Map<String, dynamic>> deleteContest(int id) async {
  try {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    String? token = prefs.getString('token');

    final response = await http.delete(
      Uri.parse('$baseUrl/competitions/delete/$id'),
      headers: {
        "accept": "application/json",
        "Content-Type": "application/json",
        if (token != null) "Authorization": "Bearer $token",
      },
    );

    print("Request Headers: ${response.request?.headers}");
    print("Response Status: ${response.statusCode}");
    print("Response Body: ${response.body}");

    return response.statusCode == 204
        ? {'statusCode': response.statusCode, 'message': 'Contest deleted successfully'}
        : {'statusCode': response.statusCode, 'error': response.body};
  } catch (e) {
    debugPrint("deleteContest error: $e");
    return {'statusCode': 503, 'error': 'Service Unavailable'};
  }
}

class ContestDetailScreen extends StatefulWidget {
  final Contest contest;

  const ContestDetailScreen({Key? key, required this.contest}) : super(key: key);

  @override
  State<ContestDetailScreen> createState() => _ContestDetailScreenState();
}

class _ContestDetailScreenState extends State<ContestDetailScreen> {
  List<Comment> comments = [];
  final TextEditingController commentController = TextEditingController();
  String userName = "사용자";

  @override
  void initState() {
    super.initState();
    _loadUserName();
  }

  Future<void> _loadUserName() async {
    SharedPreferences prefs = await SharedPreferences.getInstance();
    setState(() {
      userName = prefs.getString('userName') ?? "사용자";
    });
  }

  void addComment(String content) {
    setState(() {
      comments.add(Comment(
          userName: userName, content: content, date: DateTime.now()));
    });
    commentController.clear();
  }

  Future<void> _deleteContest(BuildContext context) async {
    final result = await deleteContest(widget.contest.id!);
    if (result['statusCode'] == 204) {
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text("${widget.contest.title} 공모전이 삭제되었습니다.")),
      );
    } else {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text("삭제 실패: ${result['error']}")),
      );
    }
  }

  @override
  void dispose() {
    commentController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    bool isDarkMode = Theme.of(context).brightness == Brightness.dark;

    print('Using local image file: ${widget.contest.imageFile}');
    print('Local file exists: ${widget.contest.imageFile != null && widget.contest.imageFile!.isNotEmpty && File(widget.contest.imageFile!).existsSync()}');
    print('Detail Screen - imageFile: ${widget.contest.imageFile}');
    print('Detail Screen - imageUrl: ${widget.contest.imageUrl}');

    return Scaffold(
      appBar: AppBar(
        backgroundColor: isDarkMode ? Colors.grey[850] : Colors.blueAccent,
        foregroundColor: Colors.white,
        title: Text(widget.contest.title),
        actions: [
          IconButton(
            icon: Icon(Icons.delete),
            onPressed: () => _showDeleteConfirmationDialog(context),
          ),
        ],
      ),
      body: SingleChildScrollView(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Center(
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(12.0),
                  child: SizedBox(
                    height: 400,
                    width: double.infinity,
                    child: widget.contest.imageFile != null &&
                        widget.contest.imageFile!.isNotEmpty &&
                        File(widget.contest.imageFile!).existsSync()
                        ? Image.file(
                      File(widget.contest.imageFile!),
                      fit: BoxFit.contain,
                      errorBuilder: (context, error, stackTrace) {
                        return Image.asset('assets/img/sample_poster.png');
                      },
                    )
                        : (widget.contest.imageUrl.isNotEmpty
                        ? Image.network(
                      widget.contest.imageUrl,
                      fit: BoxFit.contain,
                      errorBuilder: (context, error, stackTrace) {
                        return Image.asset('assets/img/sample_poster.png');
                      },
                    )
                        : Image.asset('assets/img/sample_poster.png')),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              buildInfoSection(),
              const SizedBox(height: 16),
              buildDescriptionSection(),
              const Divider(height: 40, thickness: 2),
              buildCommentSection(),
            ],
          ),
        ),
      ),
    );
  }

  void _showDeleteConfirmationDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          title: Text("삭제 확인"),
          content: Text("${widget.contest.title} 공모전을 삭제하시겠습니까?"),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: Text("취소"),
            ),
            ElevatedButton(
              onPressed: () {
                Navigator.pop(context);
                _deleteContest(context);
              },
              child: Text("삭제"),
            ),
          ],
        );
      },
    );
  }

  Widget buildInfoSection() {
    return Card(
      elevation: 5,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12.0)),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            buildInfoRow(Icons.title, "공모전 이름", widget.contest.title),
            const Divider(),
            buildInfoRow(Icons.account_circle, "주최자", widget.contest.organizer),
            const Divider(),
            buildInfoRow(Icons.location_on, "공모전 장소", widget.contest.location),
            const Divider(),
            buildInfoRow(
              Icons.date_range,
              "신청 기간",
              "${DateFormat('yyyy-MM-dd').format(widget.contest.applicationStart)} ~ ${DateFormat('yyyy-MM-dd').format(widget.contest.applicationEnd)}",
            ),
            const Divider(),
            buildInfoRow(
              Icons.event,
              "공모전 기간",
              "${DateFormat('yyyy-MM-dd').format(widget.contest.startDate)} ~ ${DateFormat('yyyy-MM-dd').format(widget.contest.endDate)}",
            ),
            const Divider(),
            buildInfoRow(Icons.link, "신청 경로", widget.contest.applicationLink),
            const Divider(),
            buildInfoRow(Icons.phone, "지원 연락처", widget.contest.contact),
          ],
        ),
      ),
    );
  }

  Widget buildDescriptionSection() {
    return Card(
      color: Colors.grey[200],
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12.0)),
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              "공모전 설명",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            Text(
              widget.contest.description,
              style: const TextStyle(fontSize: 16, height: 1.5),
            ),
          ],
        ),
      ),
    );
  }

  DateTime? parseDate(String dateStr) {
    List<String> formats = [
      'yyyy-MM-dd',
      'yyyy.MM.dd',
      'yyyy년 MM월 dd일',
    ];

    for (var format in formats) {
      try {
        return DateFormat(format).parseStrict(dateStr);
      } catch (e) {
        // 실패하면 다음 형식으로 넘어갑니다.
      }
    }
    return null;
  }

  Widget buildInfoRow(IconData icon, String label, String value) {
    DateTime? date = parseDate(value);
    String formattedDate = date != null ? DateFormat('yyyy-MM-dd').format(date) : value;

    return Row(
      children: [
        Icon(icon, color: Colors.blueAccent),
        const SizedBox(width: 16),
        Text(
          "$label: ",
          style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
        ),
        Expanded(
          child: Text(
            formattedDate,
            style: const TextStyle(fontSize: 16),
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ],
    );
  }

  Widget buildCommentSection() {
    return Card(
      elevation: 5,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12.0)),
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              "댓글",
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            ListView.builder(
              shrinkWrap: true,
              physics: NeverScrollableScrollPhysics(),
              itemCount: comments.length,
              itemBuilder: (context, index) {
                final comment = comments[index];
                return ListTile(
                  title: Text(
                    comment.userName,
                    style: TextStyle(fontWeight: FontWeight.bold),
                  ),
                  subtitle: Text(comment.content),
                  trailing: Text(
                    DateFormat('yyyy-MM-dd HH:mm').format(comment.date),
                    style: TextStyle(fontSize: 12, color: Colors.grey),
                  ),
                );
              },
            ),
            const Divider(height: 20, thickness: 1),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: commentController,
                    decoration: InputDecoration(
                      hintText: "댓글을 입력하세요",
                      border: OutlineInputBorder(),
                    ),
                  ),
                ),
                IconButton(
                  icon: Icon(Icons.send),
                  onPressed: () {
                    if (commentController.text.isNotEmpty) {
                      addComment(commentController.text);
                    }
                  },
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
