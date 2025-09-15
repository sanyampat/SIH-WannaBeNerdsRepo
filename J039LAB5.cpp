#include <cstdlib>
#include <iostream>

using namespace std;

struct Node {
    int data;
    Node* next;
};

Node* START = NULL;
Node* AVAIL = NULL;

void createList(int n) {
    Node* temp, *ptr;
    for (int i = 0; i < n; i++) {
        temp = new Node;
        cout << "Enter element " << i + 1 << ": ";
        cin >> temp->data;
        temp->next = NULL;
        if (START == NULL) {
            START = temp;
        } else {
            ptr = START;
            while (ptr->next != NULL) {
                ptr = ptr->next;
            }
            ptr->next = temp;
        }
    }
}

void traverse() {
    Node* ptr = START;
    if (ptr == NULL) {
        cout << "List is empty!\n";
        return;
    }
    cout << "Linked List: ";
    while (ptr != NULL) {
        cout << ptr->data << " ";
        ptr = ptr->next;
    }
    cout << endl;
}

void insertAtBeginning(int val) {
    Node* newNode = new Node;
    newNode->data = val;
    newNode->next = START;
    START = newNode;
}

void insertAtEnd(int val) {
    Node* newNode = new Node;
    newNode->data = val;
    newNode->next = NULL;
    if (START == NULL) {
        START = newNode;
        return;
    }
    Node* ptr = START;
    while (ptr->next != NULL) {
        ptr = ptr->next;
    }
    ptr->next = newNode;
}

void insertAfter(int num, int val) {
    Node* ptr = START;
    while (ptr != NULL && ptr->data != num) {
        ptr = ptr->next;
    }
    if (ptr == NULL) {
        cout << "Node with value " << num << " not found.\n";
        return;
    }
    Node* newNode = new Node;
    newNode->data = val;
    newNode->next = ptr->next;
    ptr->next = newNode;
}

void insertBefore(int num, int val) {
    if (START == NULL) {
        cout << "List is empty.\n";
        return;
    }
    if (START->data == num) {
        insertAtBeginning(val);
        return;
    }
    Node* ptr = START, *preptr = NULL;
    while (ptr != NULL && ptr->data != num) {
        preptr = ptr;
        ptr = ptr->next;
    }
    if (ptr == NULL) {
        cout << "Node with value " << num << " not found.\n";
        return;
    }
    Node* newNode = new Node;
    newNode->data = val;
    newNode->next = ptr;
    preptr->next = newNode;
}

void deleteFirst() {
    if (START == NULL) {
        cout << "UNDERFLOW - List empty.\n";
        return;
    }
    Node* ptr = START;
    START = START->next;
    delete ptr;
}

void deleteLast() {
    if (START == NULL) {
        cout << "UNDERFLOW - List empty.\n";
        return;
    }
    Node* ptr = START, *preptr = NULL;
    while (ptr->next != NULL) {
        preptr = ptr;
        ptr = ptr->next;
    }
    if (preptr == NULL) {
        START = NULL;
    } else {
        preptr->next = NULL;
    }
    delete ptr;
}

void deleteAfter(int num) {
    Node* ptr = START;
    while (ptr != NULL && ptr->data != num) {
        ptr = ptr->next;
    }
    if (ptr == NULL || ptr->next == NULL) {
        cout << "No node exists after " << num << ".\n";
        return;
    }
    Node* temp = ptr->next;
    ptr->next = temp->next;
    delete temp;
}
void insertAtPosition(int pos, int val) {
    Node* newNode = new Node;
    newNode->data = val;
    if (pos == 1) {
        newNode->next = START;
        START = newNode;
        return;
    }
    Node* ptr = START;
    for (int i = 1; ptr != NULL && i < pos - 1; i++) {
        ptr = ptr->next;
    }
    if (ptr == NULL) {
        cout << "Position out of range!\n";
        delete newNode;
        return;
    }
    newNode->next = ptr->next;
    ptr->next = newNode;
}
void deleteAtPosition(int pos) {
    if (START == NULL) {
        cout << "UNDERFLOW - List empty.\n";
        return;
    }
    Node* temp = START;
    if (pos == 1) {
        START = START->next;
        delete temp;
        return;
    }
    Node* prev = NULL;
    for (int i = 1; temp != NULL && i < pos; i++) {
        prev = temp;
        temp = temp->next;
    }
    if (temp == NULL) {
        cout << "Position out of range!\n";
        return;
    }
    prev->next = temp->next;
    delete temp;
}
void reverseList() {
    Node* prev = NULL, *curr = START, *next = NULL;
    while (curr != NULL) {
        next = curr->next;
        curr->next = prev;
        prev = curr;
        curr = next;
    }
    START = prev;
}
void removeDuplicates() {
    Node* curr = START;
    while (curr != NULL && curr->next != NULL) {
        if (curr->data == curr->next->data) {
            Node* temp = curr->next;
            curr->next = curr->next->next;
            delete temp;
        } else {
            curr = curr->next;
        }
    }
}

int main() {
    int n, choice, val, num;
    cout << "Enter number of elements in initial linked list: ";
    cin >> n;
    createList(n);

    do {
        cout << "\n--- MENU ---\n";
        cout << "1. Traverse\n";
        cout << "2. Insert at Beginning\n";
        cout << "3. Insert at End\n";
        cout << "4. Insert After Node\n";
        cout << "5. Insert Before Node\n";
        cout << "6. Insert at Specific Position\n";
        cout << "7. Delete First Node\n";
        cout << "8. Delete Last Node\n";
        cout << "9. Delete After Node\n";
        cout << "10. Delete at Specific Position\n";
        cout << "11. Reverse Linked List\n";
        cout << "12. Remove Duplicates (Sorted List)\n";
        cout << "13. Exit\n";
        cout << "Enter your choice: ";
        cin >> choice;

        switch (choice) {
        case 1:
            traverse();
            break;
        case 2:
            cout << "Enter value to insert: ";
            cin >> val;
            insertAtBeginning(val);
            break;
        case 3:
            cout << "Enter value to insert: ";
            cin >> val;
            insertAtEnd(val);
            break;
        case 4:
            cout << "Enter value after which to insert: ";
            cin >> num;
            cout << "Enter value to insert: ";
            cin >> val;
            insertAfter(num, val);
            break;
        case 5:
            cout << "Enter value before which to insert: ";
            cin >> num;
            cout << "Enter value to insert: ";
            cin >> val;
            insertBefore(num, val);
            break;
        case 6:
            cout << "Enter position: ";
            cin >> num;
            cout << "Enter value to insert: ";
            cin >> val;
            insertAtPosition(num, val);
            break;
        case 7:
            deleteFirst();
            break;
        case 8:
            deleteLast();
            break;
        case 9:
            cout << "Enter value after which to delete: ";
            cin >> num;
            deleteAfter(num);
            break;
        case 10:
            cout << "Enter position to delete: ";
            cin >> num;
            deleteAtPosition(num);
            break;
        case 11:
            reverseList();
            cout << "List reversed.\n";
            break;
        case 12:
            removeDuplicates();
            cout << "Duplicates removed (if any).\n";
            break;
        case 13:
            cout << "Exiting...\n";
            break;
        default:
            cout << "Invalid choice.\n";
        }
    } while (choice != 13);

    return 0;
}
