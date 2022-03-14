use crate::tools;
use cosmian_bls12_381::{G1Projective, Scalar};
use eyre::Result;
use std::convert::TryFrom;
use std::ops::AddAssign;
use std::time::SystemTime;
use std::{
    iter::Sum,
    ops::{Add, Deref, DerefMut, Mul},
};

/// DMCFE `T` matrix
#[derive(Clone, Default)]
pub struct TMat<T>(pub(crate) [[T; 2]; 2]);

impl<T> Deref for TMat<T> {
    type Target = [[T; 2]; 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for TMat<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, 'b, T, U> Mul<&'b DVec<U>> for &'a TMat<T>
where
    &'a T: Mul<&'b U>,
    <&'a T as Mul<&'b U>>::Output: Add<Output = <&'a T as Mul<&'b U>>::Output>,
{
    type Output = DVec<<<&'a T as Mul<&'b U>>::Output as Add>::Output>;

    fn mul(self, rhs: &'b DVec<U>) -> Self::Output {
        DVec([
            &self[0][0] * &rhs[0] + &self[0][1] * &rhs[1],
            &self[1][0] * &rhs[0] + &self[1][1] * &rhs[1],
        ])
    }
}

impl<'a, 'b, T> Mul<&'a G1Projective> for &'b TMat<T>
where
    T: 'b,
    &'b T: Mul<&'a G1Projective>,
{
    type Output = TMat<<&'b T as Mul<&'a G1Projective>>::Output>;

    fn mul(self, rhs: &'a G1Projective) -> Self::Output {
        TMat::new(
            &self[0][0] * rhs,
            &self[0][1] * rhs,
            &self[1][0] * rhs,
            &self[1][1] * rhs,
        )
    }
}

impl<T> TMat<T> {
    pub fn new(a: T, b: T, c: T, d: T) -> Self {
        TMat([[a, b], [c, d]])
    }
}

impl TMat<Scalar> {
    /// Generate `T_i` such that `Sum(T_i) = 0`.
    /// l       : label
    /// mat_list: list of ecrypted `t_i`
    pub fn encrypt(self, l: &Label, mat_list: &[TMat<G1Projective>]) -> Self {
        let mut res = [[Scalar::zero(); 2]; 2];
        for i in 0..2 {
            for j in 0..2 {
                res[i][j] = mat_list
                    .iter()
                    .map(|tj| tools::h(l.as_ref(), &self[i][j], &tj[i][j]))
                    .sum()
            }
        }
        TMat(res)
    }
}

/// 2 dimensional vector
#[derive(Clone, Copy, Default)]
pub struct DVec<T>(pub(crate) [T; 2]);

impl<T> DVec<T> {
    pub fn new(a: (T, T)) -> Self {
        DVec([a.0, a.1])
    }
}

impl<T: Clone> DVec<T> {
    /// Convert a DVec into a vector of size 2
    pub fn to_vec(&self) -> Vec<T> {
        vec![self[0].clone(), self[1].clone()]
    }

    pub fn inner_product<U: Clone>(&self, v: &DVec<U>) -> <<T as Mul<U>>::Output as Add>::Output
    where
        T: Mul<U>,
        <T as Mul<U>>::Output: Add,
    {
        self[0].clone() * v[0].clone() + self[1].clone() * v[1].clone()
    }
}

impl<T> Deref for DVec<T> {
    type Target = [T; 2];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a, 'b, T, U> Mul<&'a U> for &'b DVec<T>
where
    T: 'b,
    &'b T: Mul<&'a U>,
{
    type Output = DVec<<&'b T as Mul<&'a U>>::Output>;

    fn mul(self, rhs: &'a U) -> Self::Output {
        DVec([&self[0] * rhs, &self[1] * rhs])
    }
}

impl<T> Add for DVec<T>
where
    T: Add<Output = T> + Clone,
{
    type Output = DVec<T>;

    fn add(mut self, rhs: Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<T> AddAssign for DVec<T>
where
    T: Add<Output = T> + Clone,
{
    fn add_assign(&mut self, rhs: Self) {
        *self = DVec([
            self[0].clone() + rhs[0].clone(),
            self[1].clone() + rhs[1].clone(),
        ]);
    }
}

impl<T> Sum for DVec<T>
where
    T: Add<Output = T> + Clone + Default,
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut res = Default::default();
        for dvec in iter {
            res += dvec;
        }
        res
    }
}

impl<T: Clone> IntoIterator for DVec<T> {
    type Item = T;

    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        #[allow(clippy::unnecessary_to_owned)]
        self.0.to_vec().into_iter()
    }
}

impl<'a, T> TryFrom<&'a Vec<T>> for DVec<T>
where
    T: Clone,
{
    type Error = &'static str;

    fn try_from(value: &'a Vec<T>) -> Result<Self, Self::Error> {
        match value.len() {
            2 => Ok(DVec([value[0].clone(), value[1].clone()])),
            _ => Err("SizeError"),
        }
    }
}

/// DMCFE label
#[derive(Clone)]
pub struct Label(Vec<u8>);

impl Label {
    /// Get the timestamp as a label. Round to minutes.
    pub fn new() -> Result<Self> {
        Ok(Self(
            (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs()
                / 60)
                .to_be_bytes()
                .to_vec(),
        ))
    }

    pub fn aggregate(&mut self, r: &[u8]) {
        self.0.append(&mut r.to_vec());
    }
}

impl From<&str> for Label {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<&[Scalar]> for Label {
    fn from(v: &[Scalar]) -> Self {
        let mut res: Vec<u8> = vec![];
        v.iter()
            .for_each(|val| res.append(&mut val.to_bytes().to_vec()));
        Label(res)
    }
}
impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
