<?php
// api.php
session_start();
header('Content-Type: application/json');

// --- DATABASE CONNECTION ---
$host = '127.0.0.1';
$db_name = 'aims_db';
$username = 'root';
$password = '';

try {
    $conn = new PDO("mysql:host=" . $host . ";dbname=" . $db_name, $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $conn->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
} catch(PDOException $exception) {
    http_response_code(500);
    echo json_encode(["error" => "Database connection error: " . $exception->getMessage()]);
    exit;
}

// --- AUTH HELPER FUNCTIONS ---
function is_logged_in() {
    return isset($_SESSION['user_id']);
}
function get_user_role() {
    return $_SESSION['role'] ?? null;
}
function check_auth($allowed_roles = []) {
    if (!is_logged_in()) {
        http_response_code(401);
        echo json_encode(["error" => "Unauthorized"]);
        exit;
    }
    if (!empty($allowed_roles) && !in_array(get_user_role(), $allowed_roles)) {
        http_response_code(403);
        echo json_encode(["error" => "Forbidden: Insufficient permissions"]);
        exit;
    }
}
function log_activity($conn, $user_id, $action, $details) {
    $stmt = $conn->prepare("INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)");
    $stmt->execute([$user_id, $action, json_encode($details)]);
}

// --- ROUTER ---
$action = $_GET['action'] ?? '';
$data = json_decode(file_get_contents("php://input"));

try {
    switch ($action) {
        
        // --- AUTH ---
        case 'login':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            if (!isset($data->email) || !isset($data->password)) throw new Exception("Email and password required");
            $stmt = $conn->prepare("SELECT id, email, password_hash, role FROM users WHERE email = ?");
            $stmt->execute([$data->email]);
            $user = $stmt->fetch();
            if ($user && password_verify($data->password, $user['password_hash'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['email'] = $user['email'];
                log_activity($conn, $user['id'], 'LOGIN', ['email' => $user['email']]);
                echo json_encode(["message" => "Login successful", "user" => ["id" => $user['id'], "email" => $user['email'], "role" => $user['role']]]);
            } else {
                http_response_code(401);
                echo json_encode(["error" => "Invalid email or password"]);
            }
            break;

        case 'register':
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            if (!isset($data->email) || !isset($data->password)) throw new Exception("Email and password required");
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$data->email]);
            if ($stmt->rowCount() > 0) throw new Exception("Email already exists");
            $hash = password_hash($data->password, PASSWORD_BCRYPT);
            $stmt = $conn->prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'viewer')");
            $stmt->execute([$data->email, $hash]);
            echo json_encode(["message" => "User registered successfully"]);
            break;

        case 'me':
            check_auth();
            echo json_encode(["user" => ["id" => $_SESSION['user_id'], "email" => $_SESSION['email'], "role" => $_SESSION['role']]]);
            break;

        case 'logout':
            session_destroy();
            echo json_encode(["message" => "Logged out"]);
            break;

        // --- DASHBOARD ---
        case 'dashboard_metrics':
            check_auth(['admin', 'staff']);
            $metrics = [];
            $metrics['total_products'] = $conn->query("SELECT COUNT(*) FROM products")->fetchColumn();
            $metrics['total_categories'] = $conn->query("SELECT COUNT(*) FROM categories")->fetchColumn();
            $metrics['total_inventory_value'] = $conn->query("SELECT COALESCE(SUM(quantity * price), 0) FROM products")->fetchColumn();
            $metrics['low_stock_count'] = $conn->query("SELECT COUNT(*) FROM products WHERE quantity <= low_stock_limit")->fetchColumn();
            
            $catDist = $conn->query("SELECT c.name, COUNT(p.id) as count FROM products p LEFT JOIN categories c ON p.category_id = c.id GROUP BY p.category_id")->fetchAll();
            $lowStockItems = $conn->query("SELECT name, quantity, low_stock_limit FROM products WHERE quantity <= low_stock_limit ORDER BY quantity ASC LIMIT 10")->fetchAll();
            
            echo json_encode(["metrics" => $metrics, "charts" => ["category_distribution" => $catDist, "low_stock_items" => $lowStockItems]]);
            break;

        case 'logs_read':
            check_auth(['admin', 'staff']);
            $stmt = $conn->query("SELECT l.*, u.email as user_email FROM activity_logs l LEFT JOIN users u ON l.user_id = u.id ORDER BY l.created_at DESC LIMIT 50");
            echo json_encode($stmt->fetchAll());
            break;

        // --- PRODUCTS ---
        case 'products_read':
            check_auth();
            $query = "SELECT p.*, c.name as category_name FROM products p LEFT JOIN categories c ON p.category_id = c.id ORDER BY p.created_at DESC";
            echo json_encode($conn->query($query)->fetchAll());
            break;

        case 'products_create':
            check_auth(['admin', 'staff']);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            $stmt = $conn->prepare("INSERT INTO products (name, category_id, quantity, price, supplier, low_stock_limit) VALUES (?, ?, ?, ?, ?, ?)");
            $stmt->execute([$data->name, $data->category_id ?: null, $data->quantity, $data->price, $data->supplier, $data->low_stock_limit]);
            log_activity($conn, $_SESSION['user_id'], 'ADD_PRODUCT', ['name' => $data->name]);
            echo json_encode(["message" => "Product created"]);
            break;

        case 'products_update':
            check_auth(['admin', 'staff']);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            $stmt = $conn->prepare("SELECT * FROM products WHERE id = ?");
            $stmt->execute([$data->id]);
            $old = $stmt->fetch();
            if (!$old) throw new Exception("Product not found");
            
            $stmt = $conn->prepare("UPDATE products SET name=?, category_id=?, quantity=?, price=?, supplier=?, low_stock_limit=? WHERE id=?");
            $stmt->execute([$data->name, $data->category_id ?: null, $data->quantity, $data->price, $data->supplier, $data->low_stock_limit, $data->id]);
            log_activity($conn, $_SESSION['user_id'], 'UPDATE_PRODUCT', ['product_id' => $data->id, 'old' => $old, 'new' => $data]);
            echo json_encode(["message" => "Product updated"]);
            break;

        case 'products_delete':
            check_auth(['admin']);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            $stmt = $conn->prepare("SELECT name FROM products WHERE id = ?");
            $stmt->execute([$data->id]);
            $pName = $stmt->fetchColumn();
            
            $stmt = $conn->prepare("DELETE FROM products WHERE id = ?");
            $stmt->execute([$data->id]);
            log_activity($conn, $_SESSION['user_id'], 'DELETE_PRODUCT', ['product_id' => $data->id, 'name' => $pName]);
            echo json_encode(["message" => "Product deleted"]);
            break;

        // --- CATEGORIES ---
        case 'categories_read':
            check_auth();
            echo json_encode($conn->query("SELECT * FROM categories ORDER BY name")->fetchAll());
            break;

        case 'categories_create':
            check_auth(['admin', 'staff']);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            $stmt = $conn->prepare("INSERT INTO categories (name, description) VALUES (?, ?)");
            $stmt->execute([$data->name, $data->description]);
            log_activity($conn, $_SESSION['user_id'], 'ADD_CATEGORY', ['name' => $data->name]);
            echo json_encode(["message" => "Category created"]);
            break;
            
        case 'categories_update':
            check_auth(['admin', 'staff']);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            $stmt = $conn->prepare("UPDATE categories SET name=?, description=? WHERE id=?");
            $stmt->execute([$data->name, $data->description, $data->id]);
            echo json_encode(["message" => "Category updated"]);
            break;

        case 'categories_delete':
            check_auth(['admin']);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            $stmt = $conn->prepare("DELETE FROM categories WHERE id = ?");
            $stmt->execute([$data->id]);
            log_activity($conn, $_SESSION['user_id'], 'DELETE_CATEGORY', ['category_id' => $data->id]);
            echo json_encode(["message" => "Category deleted"]);
            break;

        // --- USERS ---
        case 'users_read':
            check_auth(['admin']);
            echo json_encode($conn->query("SELECT id, email, role, created_at FROM users ORDER BY created_at DESC")->fetchAll());
            break;

        case 'users_create':
            check_auth(['admin']);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            if (!isset($data->email) || !isset($data->password) || !isset($data->role)) throw new Exception("Missing required fields");
            
            $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$data->email]);
            if ($stmt->rowCount() > 0) throw new Exception("Email already exists");
            
            $hash = password_hash($data->password, PASSWORD_BCRYPT);
            $stmt = $conn->prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)");
            $stmt->execute([$data->email, $hash, $data->role]);
            
            $newId = $conn->lastInsertId();
            log_activity($conn, $_SESSION['user_id'], 'CREATE_USER', ['new_user_id' => $newId, 'email' => $data->email, 'role' => $data->role]);
            echo json_encode(["message" => "User created successfully"]);
            break;

        case 'users_update_role':
            check_auth(['admin']);
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            if ($data->id == $_SESSION['user_id']) throw new Exception("Cannot change own role");
            $stmt = $conn->prepare("UPDATE users SET role = ? WHERE id = ?");
            $stmt->execute([$data->role, $data->id]);
            log_activity($conn, $_SESSION['user_id'], 'UPDATE_ROLE', ['target_user_id' => $data->id, 'new_role' => $data->role]);
            echo json_encode(["message" => "Role updated"]);
            break;

        // --- CART ---
        case 'cart_add':
            check_auth();
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            if (!isset($data->product_id) || !isset($data->quantity) || $data->quantity <= 0) throw new Exception("Invalid input");
            
            $conn->beginTransaction();
            try {
                // Check stock
                $stmt = $conn->prepare("SELECT quantity FROM products WHERE id = ? FOR UPDATE");
                $stmt->execute([$data->product_id]);
                $product = $stmt->fetch();
                if (!$product) throw new Exception("Product not found");
                if ($product['quantity'] < $data->quantity) throw new Exception("Insufficient stock");
                
                // Reduce stock
                $stmt = $conn->prepare("UPDATE products SET quantity = quantity - ? WHERE id = ?");
                $stmt->execute([$data->quantity, $data->product_id]);
                
                // Add or update cart
                $stmt = $conn->prepare("INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE quantity = quantity + ?");
                $stmt->execute([$_SESSION['user_id'], $data->product_id, $data->quantity, $data->quantity]);
                
                $conn->commit();
                echo json_encode(["message" => "Added to Cart"]);
            } catch (Exception $e) {
                $conn->rollBack();
                throw $e;
            }
            break;

        case 'cart_update':
            check_auth();
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            if (!isset($data->product_id) || !isset($data->new_quantity) || $data->new_quantity < 0) throw new Exception("Invalid input");
            
            $conn->beginTransaction();
            try {
                $stmt = $conn->prepare("SELECT quantity FROM cart WHERE user_id = ? AND product_id = ? FOR UPDATE");
                $stmt->execute([$_SESSION['user_id'], $data->product_id]);
                $cartItem = $stmt->fetch();
                if (!$cartItem) throw new Exception("Item not in cart");
                
                $old_quantity = $cartItem['quantity'];
                $diff = $data->new_quantity - $old_quantity;
                
                if ($diff > 0) {
                    // Check if stock available
                    $stmt = $conn->prepare("SELECT quantity FROM products WHERE id = ? FOR UPDATE");
                    $stmt->execute([$data->product_id]);
                    $product = $stmt->fetch();
                    if ($product['quantity'] < $diff) throw new Exception("Insufficient stock");
                    
                    // Reduce stock
                    $stmt = $conn->prepare("UPDATE products SET quantity = quantity - ? WHERE id = ?");
                    $stmt->execute([$diff, $data->product_id]);
                } else if ($diff < 0) {
                    // Restore stock
                    $stmt = $conn->prepare("UPDATE products SET quantity = quantity + ? WHERE id = ?");
                    $stmt->execute([abs($diff), $data->product_id]);
                }
                
                if ($data->new_quantity == 0) {
                    $stmt = $conn->prepare("DELETE FROM cart WHERE user_id = ? AND product_id = ?");
                    $stmt->execute([$_SESSION['user_id'], $data->product_id]);
                } else {
                    $stmt = $conn->prepare("UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?");
                    $stmt->execute([$data->new_quantity, $_SESSION['user_id'], $data->product_id]);
                }
                
                $conn->commit();
                echo json_encode(["message" => "Cart updated"]);
            } catch (Exception $e) {
                $conn->rollBack();
                throw $e;
            }
            break;

        case 'cart_remove':
            check_auth();
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception("Method not allowed");
            if (!isset($data->product_id)) throw new Exception("Invalid input");
            
            $conn->beginTransaction();
            try {
                $stmt = $conn->prepare("SELECT quantity FROM cart WHERE user_id = ? AND product_id = ? FOR UPDATE");
                $stmt->execute([$_SESSION['user_id'], $data->product_id]);
                $cartItem = $stmt->fetch();
                if (!$cartItem) throw new Exception("Item not in cart");
                
                // Restore stock
                $stmt = $conn->prepare("UPDATE products SET quantity = quantity + ? WHERE id = ?");
                $stmt->execute([$cartItem['quantity'], $data->product_id]);
                
                // Remove from cart
                $stmt = $conn->prepare("DELETE FROM cart WHERE user_id = ? AND product_id = ?");
                $stmt->execute([$_SESSION['user_id'], $data->product_id]);
                
                $conn->commit();
                echo json_encode(["message" => "Removed from Cart"]);
            } catch (Exception $e) {
                $conn->rollBack();
                throw $e;
            }
            break;

        case 'cart_read':
            check_auth();
            $stmt = $conn->prepare("SELECT c.product_id, c.quantity, p.name, p.price FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $items = $stmt->fetchAll();
            
            $total = 0;
            foreach ($items as &$item) {
                $item['subtotal'] = $item['price'] * $item['quantity'];
                $total += $item['subtotal'];
            }
            
            echo json_encode(["items" => $items, "total" => $total]);
            break;

        default:
            http_response_code(404);
            echo json_encode(["error" => "Unknown action"]);
            break;
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode(["error" => $e->getMessage()]);
}
