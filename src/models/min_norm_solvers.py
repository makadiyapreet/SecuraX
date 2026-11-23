"""
min_norm_solvers.py — Minimum Norm Solvers for Multi-Objective Optimization (MOO).

Adapted from AIBugHunter (Fu et al., Empirical Software Engineering, 2024 /
Sener & Koltun, NeurIPS 2018 "Multi-Task Learning as Multi-Objective Optimization").

Finds the Pareto-optimal gradient mixture weights alpha_i in the convex hull of
task gradients via the Frank-Wolfe / Projected Gradient Descent algorithm.
"""

import numpy as np
import torch


class MinNormSolver:
    MAX_ITER = 250
    STOP_CRIT = 1e-5

    @staticmethod
    def _min_norm_element_from2(v1v1, v1v2, v2v2):
        """Analytical solution for min_{c} |c*x_1 + (1-c)*x_2|_2^2."""
        if v1v2 >= v1v1:
            gamma = 0.999
            cost = v1v1
            return gamma, cost
        if v1v2 >= v2v2:
            gamma = 0.001
            cost = v2v2
            return gamma, cost
        denom = (v1v1 + v2v2 - 2 * v1v2)
        if abs(denom) < 1e-12:
            return 0.5, v1v1
        gamma = -1.0 * ((v1v2 - v2v2) / denom)
        cost = v2v2 + gamma * (v1v2 - v2v2)
        return gamma, cost

    @staticmethod
    def _min_norm_2d(vecs, dps):
        dmin = 1e8
        sol = [(0, 1), 0.5, 1.0]
        for i in range(len(vecs)):
            for j in range(i + 1, len(vecs)):
                if (i, j) not in dps:
                    dps[(i, j)] = 0.0
                    for k in range(len(vecs[i])):
                        dps[(i, j)] += torch.mul(vecs[i][k], vecs[j][k]).sum().item()
                    dps[(j, i)] = dps[(i, j)]
                if (i, i) not in dps:
                    dps[(i, i)] = 0.0
                    for k in range(len(vecs[i])):
                        dps[(i, i)] += torch.mul(vecs[i][k], vecs[i][k]).sum().item()
                if (j, j) not in dps:
                    dps[(j, j)] = 0.0
                    for k in range(len(vecs[i])):
                        dps[(j, j)] += torch.mul(vecs[j][k], vecs[j][k]).sum().item()
                c, d = MinNormSolver._min_norm_element_from2(dps[(i, i)], dps[(i, j)], dps[(j, j)])
                if d < dmin:
                    dmin = d
                    sol = [(i, j), c, d]
        return sol, dps

    @staticmethod
    def _projection2simplex(y):
        m = len(y)
        sorted_y = np.flip(np.sort(y), axis=0)
        tmpsum = 0.0
        tmax_f = (np.sum(y) - 1.0) / m
        for i in range(m - 1):
            tmpsum += sorted_y[i]
            tmax = (tmpsum - 1) / (i + 1.0)
            if tmax > sorted_y[i + 1]:
                tmax_f = tmax
                break
        return np.maximum(y - tmax_f, np.zeros(y.shape))

    @staticmethod
    def _next_point(cur_val, grad, n):
        proj_grad = grad - (np.sum(grad) / n)
        tm1 = -1.0 * cur_val[proj_grad < 0] / (proj_grad[proj_grad < 0] + 1e-12)
        tm2 = (1.0 - cur_val[proj_grad > 0]) / (proj_grad[proj_grad > 0] + 1e-12)

        t = 1.0
        if len(tm1[tm1 > 1e-7]) > 0:
            t = np.min(tm1[tm1 > 1e-7])
        if len(tm2[tm2 > 1e-7]) > 0:
            t = min(t, np.min(tm2[tm2 > 1e-7]))

        next_point = proj_grad * t + cur_val
        next_point = MinNormSolver._projection2simplex(next_point)
        return next_point

    @staticmethod
    def find_min_norm_element(vecs):
        """Given a list of flattened gradient tensors for each task,
        finds the Pareto-optimal convex scale combination sol_vec."""
        if len(vecs) == 1:
            return np.array([1.0]), 0.0

        dps = {}
        init_sol, dps = MinNormSolver._min_norm_2d(vecs, dps)

        n = len(vecs)
        sol_vec = np.zeros(n)
        sol_vec[init_sol[0][0]] = init_sol[1]
        sol_vec[init_sol[0][1]] = 1.0 - init_sol[1]

        if n < 3:
            return sol_vec, init_sol[2]

        iter_count = 0
        grad_mat = np.zeros((n, n))
        for i in range(n):
            for j in range(n):
                grad_mat[i, j] = dps[(i, j)]

        while iter_count < MinNormSolver.MAX_ITER:
            grad_dir = -1.0 * np.dot(grad_mat, sol_vec)
            new_point = MinNormSolver._next_point(sol_vec, grad_dir, n)
            v1v1 = 0.0
            v1v2 = 0.0
            v2v2 = 0.0
            for i in range(n):
                for j in range(n):
                    v1v1 += sol_vec[i] * sol_vec[j] * dps[(i, j)]
                    v1v2 += sol_vec[i] * new_point[j] * dps[(i, j)]
                    v2v2 += new_point[i] * new_point[j] * dps[(i, j)]
            nc, nd = MinNormSolver._min_norm_element_from2(v1v1, v1v2, v2v2)
            new_sol_vec = nc * sol_vec + (1.0 - nc) * new_point
            change = new_sol_vec - sol_vec
            if np.sum(np.abs(change)) < MinNormSolver.STOP_CRIT:
                return sol_vec, nd
            sol_vec = new_sol_vec
            iter_count += 1

        return sol_vec, 0.0


def gradient_normalizers(grads, losses, normalization_type="none"):
    """Normalizes task gradients prior to min norm solving."""
    gn = {}
    if normalization_type == "l2":
        for t in grads:
            gn[t] = np.sqrt(np.sum([gr.pow(2).sum().item() for gr in grads[t]])) + 1e-12
    elif normalization_type == "loss":
        for t in grads:
            gn[t] = float(losses[t]) + 1e-12
    elif normalization_type == "none":
        for t in grads:
            gn[t] = 1.0
    else:
        for t in grads:
            gn[t] = 1.0
    return gn
