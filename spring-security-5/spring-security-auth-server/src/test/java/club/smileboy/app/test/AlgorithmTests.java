package club.smileboy.app.test;

import java.util.LinkedList;
import java.util.List;

public class AlgorithmTests {
    public static void main(String[] args) {

        Integer[] values = {3,null,30,10,null,null,15,null,45};
        LinkedList<TreeNode> stack = new LinkedList<>();

        int i = 1;
        TreeNode root = new TreeNode(values[0]);
        stack.add(root);
        do {
            Integer left = values[i];
            TreeNode peek = stack.peek();
            peek.left = left != null ? new TreeNode(left) : null;
            if (i + 1 >= values.length) {
                break;
            }
            Integer right = values[i + 1];
            peek.right = right != null ? new TreeNode(right) : null;
            if (left != null) {
                stack.add(peek.left);
            }
            if (right != null) {
                stack.add(peek.right);
            }
            i += 2;
            stack.pop();
        } while (stack.size() > 0 && i < values.length);



        List<List<String>> lists = printTree(root);
        for (List<String> list : lists) {
            System.out.print("[");
            for (int i1 = 0; i1 < list.size(); i1++) {
                System.out.print(list.get(i1));
                if (i1 + 1 != list.size()) {
                    System.out.print(",");
                }
            }
            System.out.println("]");
        }
    }

    public static class TreeNode {
        int val;
        TreeNode left;
        TreeNode right;

        TreeNode() {
        }

        TreeNode(int val) {
            this.val = val;
        }

        TreeNode(int val, TreeNode left, TreeNode right) {
            this.val = val;
            this.left = left;
            this.right = right;
        }
    }

    static List<List<String>> printTree(TreeNode root) {

        if (root == null) {
            throw new UnsupportedOperationException();
        }
        // 如果 栈里面全是空,就不处理了 ...
        int depth = searchTreeDepth(root);

        // 此时高度就是深度 ..
        // 总数量为 2^n - 1;

        int total = (int) Math.pow(2, depth) - 1;

        // 深度算出来了 ..
        return  printTreeByMiddle(root, depth, new String[depth][total]);

    }

    // 深度 中序遍历
    private static List<List<String>> printTreeByMiddle(TreeNode root, int depth, String[][] array) {
        // 开始解析左右
        int middle = ((int) (Math.pow(2, depth) - 1)) / 2;
        array[0][middle] = String.valueOf(root.val);
        if(depth > 1) {
            Point point = new Point(0, middle);
            printTreeByMiddleInternal(root.left, true, point, depth, array);
            printTreeByMiddleInternal(root.right, false, point, depth, array);
        }
        LinkedList<List<String>> result = new LinkedList<>();
        for (String[] objects : array) {
            LinkedList<String> strings = new LinkedList<>();
            for (String object : objects) {
                if(object == null) {
                    strings.add("");
                }
                else {
                    strings.add(object);
                }
            }
            result.add(strings);
        }
        return result;
    }

    public static void printTreeByMiddleInternal(TreeNode node, boolean isLeft, Point parentPoint, int depth, String[][] array) {
        int y = (int) Math.pow(2, depth - parentPoint.x - 2);
        Point point = new Point();
        point.x = parentPoint.x + 1;
        // 计算自己的位置 .
        if (isLeft) {
            point.y = parentPoint.y - y;
        } else {
            point.y = parentPoint.y + y;
        }
        array[point.x][point.y] = node == null ? "" : String.valueOf(node.val);
        if(node != null) {
            if (node.left != null) {
                printTreeByMiddleInternal(node.left, true, point, depth, array);
            }
            if(node.right != null) {
                printTreeByMiddleInternal(node.right, false, point, depth, array);
            }
        }
    }


    static class Point {
        int x;
        int y;

        public Point() {

        }

        public Point(int x, int y) {
            this.x = x;
            this.y = y;
        }
    }

    /**
     * 深度优先遍历深度 ..
     * @param treeNode treeNode
     * @return 深度 ..
     */
    public static int searchTreeDepth(TreeNode treeNode) {

        if(treeNode.left == null && treeNode.right == null) {
            return 1;
        }
        int leftDepth = searchTreeDepthInternal(treeNode.left,1);
        int rightDepth = searchTreeDepthInternal(treeNode.right,1);
        return Math.max(leftDepth, rightDepth);
    }

    private static int searchTreeDepthInternal(TreeNode left, int i) {
        if(left != null) {
            int leftDepth = searchTreeDepthInternal(left.left,i + 1);
            int rightDepth = searchTreeDepthInternal(left.right,i + 1);
            return Math.max(leftDepth,rightDepth);
        }

        return i;
    }


    private static List<String> resolve(TreeNode root) {

        LinkedList<String> result = new LinkedList<>();
        LinkedList<TreeNode> stack = new LinkedList<>();
        // 如何完整的解析出来 ...
        stack.add(root);

        while (stack.size() > 0) {
            TreeNode pop = stack.pop();
            if (pop == null) {
                result.add(null);
            } else {
                result.add(String.valueOf(pop.val));
                stack.add(pop.left);
                stack.add(pop.right);
            }
        }

        int count =  0;
        for (int i = result.size() - 1; i >= 0; i--) {
            if(result.get(i) == null) {
                count ++;
                continue;
            }
            break;
        }

        return result.subList(0,result.size() - count);
    }

    // 先序遍历 ...
    public static List<List<String>> printfNTreeArray(int n, String[] tree) {
        // 数组列数
        int y = tree.length;

        String[][] mutex = new String[n][y];

        int s = 0;
        int middle = y / 2;
        // 先序遍历二叉树
        for (int i = 0; i < tree.length; i++) {
            if (s < n) {
                // 算出它的位置 ..
                if (i == 0) {
                    mutex[0][middle] = tree[0];
                    for (int i1 = 0; i1 < mutex[0].length; i1++) {
                        if (mutex[0][i1] == null) {
                            mutex[0][i1] = "";
                        }
                    }
                    s = 1;
                } else {
                    int total = (int) Math.pow(2, s);
                    int span = (int) Math.pow(2, (n - s));
                    // 表示最左边 ..
                    middle /= 2;
                    // 取出这一列的数 ...
                    for (int j = i, x = 0; j < i + total && middle + x < y; j++, x = x + span) {
                        // 位置
                        // 算出最左边的 元素位置 ..
                        mutex[s][middle + x] = tree[j] == null ? "" : tree[j];
                    }

                    for (int i1 = 0; i1 < mutex[s].length; i1++) {
                        if (mutex[s][i1] == null) {
                            mutex[s][i1] = "";
                        }
                    }

                    s++;
                    i = i + total - 1;
                }
            }
        }

        // 转换
        LinkedList<List<String>> result = new LinkedList<List<String>>();
        for (String[] objects : mutex) {
            LinkedList<String> strings = new LinkedList<>();
            for (String object : objects) {
                if(object == null) {
                    strings.add("");
                }
                else {
                    strings.add(object);
                }
            }
            result.add(strings);
        }
        return result;
    }


}
